"""Utility functions for azul-capa plugin."""

import pathlib
import re
from typing import Optional

# capa comes from flare-capa
import capa
import capa.features.extractors.elffile
import capa.features.extractors.pefile
import capa.loader
import capa.main
import capa.render.default
import capa.render.json
import capa.render.result_document as rd
import capa.render.utils
import capa.render.vverbose
import capa.rules
from capa.exceptions import (
    UnsupportedArchError,
    UnsupportedFormatError,
    UnsupportedOSError,
)
from capa.features.common import (
    FORMAT_FREEZE,
    FORMAT_PE,
    FORMAT_SC32,
    FORMAT_SC64,
    FORMAT_UNKNOWN,
    OS_AUTO,
)
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs, CsError
from elftools.common.exceptions import ELFError
from pefile import PEFormatError

BACKEND_VIV = "vivisect"
BACKEND_DOTNET = "dotnet"


class RuleError(Exception):
    """Raised when the CAPA rules are missing or cannot be parsed by CAPA."""

    pass


class CorruptFileError(Exception):
    """Raised when the source file is corrupt."""

    pass


class SignatureError(Exception):
    """Raised when the typelibs for CAPA are missing."""

    pass


def get_shellcode_type(buffer: bytes, minimum_shellcode_instructions: int = 50) -> str:
    """Attempt to determine if a given buffer looks a bit like shellcode.

    :param buffer: file contents, may be truncated
    :param minimum_shellcode_instructions: if this many instructions disassemble, assume it's all shellcode
    :return: string description of the file type
    """
    try:
        # shellcode check
        instruction_count = 0
        # valid shellcode should start at the start of the buffer,
        # currently have both architectures here
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for _address, _size, _mnemonic, _op_str in md.disasm_lite(buffer, 0x1000):
            # print("0x%x:\t%s\t%s" % (address, mnemonic, op_str))
            instruction_count += 1
            if instruction_count > minimum_shellcode_instructions:
                return FORMAT_SC64

        # try 32 bit next
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for _address, _size, _mnemonic, _op_str in md.disasm_lite(buffer, 0x1000):
            # print("0x%x:\t%s\t%s" % (address, mnemonic, op_str))
            instruction_count += 1
            if instruction_count > minimum_shellcode_instructions:
                return FORMAT_SC32

    except CsError:
        # if capstone fails, its probably not shellcode
        return FORMAT_UNKNOWN

    return FORMAT_UNKNOWN


def do_capa_processing(
    file_path: pathlib.Path,
    rules_path: list[pathlib.Path],
    sigs: pathlib.Path,
    ignore_sigs: bool,
    cache_dir: pathlib.Path,
    capa_logging: bool,
    no_prog: bool = True,
) -> Optional[dict]:
    """Process a file with CAPA and produce a dictionary of results that can be parsed to produce plugin output.

    This replicates the logic in Mandiant's capa/main.py main() and scripts/capa_as_library.py, altering it slightly
    for our use case.  This function was based on flare-capa 5.1.0 and updated for 6.1.0 and 7.1.0.

    This function will probably break during CAPA upgrades.  If it breaks and it's too difficult to fix, just call CAPA
    on the command line and parse the resulting output.

    :param filepath: path to sample to process with CAPA
    :param rules_path: list of paths to directories that contain CAPA rules files
    :param sigs: path to FLIRT sigs used by CAPA
    :param ignore_sigs: flag to ignore FLIRT sigs and process detected library functions for capabilities
    :param cache_dir: directory where cached rules files will be stored/accessed
    :raises CorruptFileError: input file is a PE or ELF, but appears to be corrupted
    :raises RuleError: raised when CAPA cannot produce a ruleset from the provided rules, implying rules are bad
    :raises SignatureError: raised when signature dir does not exist
    :returns: CAPA text report, attack info, capabilities, behaviour info
    """
    # only needed for testing to see what capa is actually doing under the hood
    if capa_logging:
        import logging

        ac_logger = logging.getLogger("capa")
        ac_logger.setLevel(logging.DEBUG)

    # if we don't think it's shellcode, check file type, return if not supported
    try:
        file_type = capa.main.get_auto_format(file_path)
        if file_type == FORMAT_FREEZE:
            # freeze format is apparently used for previous analysis or something like that
            # we don't care, just ignore any if they slip through
            return

    except PEFormatError as e:
        # PE is corrupt
        raise CorruptFileError(str(e)) from e
    except UnsupportedFormatError:
        # CAPA doesn't like it, lets check if it looks like shellcode
        with open(file_path, "rb") as f:
            content = f.read()
        # could auto reject here based on size if too long (>300KB??)
        file_type = get_shellcode_type(content)

        # is it still unknown, i.e. not shellcode
        if file_type == FORMAT_UNKNOWN:
            return

    # load rules
    try:
        # cached rules used during testing, unless they don't exist
        rules = capa.rules.get_rules(rules_path, cache_dir=cache_dir)

        # if filtering the rule set do that now

    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        # rules are bad, raise an exception so the plugin knows to die
        raise RuleError(str(e)) from e

    # get file extractors and check for any limitations that prevent analysis
    try:
        file_extractors = capa.loader.get_file_extractors(file_path, file_type)
    except (PEFormatError, ELFError, OverflowError) as e:
        # input file is corrupt, bail on it
        raise CorruptFileError(str(e)) from e

    for file_extractor in file_extractors:
        try:
            pure_file_capabilities = capa.main.find_file_capabilities(rules, file_extractor, {})
        except (PEFormatError, ELFError, OverflowError) as e:
            raise CorruptFileError(str(e)) from e

        # check for file limitations
        if capa.main.has_static_limitation(rules, pure_file_capabilities):
            # bail if there's a limitation that short-circuits processing,
            return

        if capa.main.has_dynamic_limitation(rules, pure_file_capabilities):
            # bail if there's a limitation that short-circuits processing,
            return

    # set sig_paths if we will use them
    # standalone CAPA isn't applying sigs to PEs, or keeps the excluded hits in its results.
    # output shows that its skipping 0 library functions, despite debug log showing it loading the sigs
    # there's likely an error somewhere in capa.main.get_extractor.
    try:
        if ignore_sigs:
            # pretend there aren't any typelib sigs, so we get the same wrong output as flare-capa 5.0.0
            sig_paths = []
        elif file_type == FORMAT_PE:
            # get typelib signatures for PEs
            sig_paths = capa.loader.get_signatures(sigs)
        else:
            # no need for sigs since file isn't a PE
            sig_paths = []
    except IOError as e:
        # sigs are missing and we need them
        raise SignatureError(str(e)) from e

    # I don't think we can benefit from this
    should_save_workspace = False

    # get an extractor
    try:
        # need to specify different backend for dotnet files
        backend = BACKEND_DOTNET if file_type == "dotnet" else BACKEND_VIV

        extractor = capa.loader.get_extractor(
            file_path, file_type, OS_AUTO, backend, sig_paths, should_save_workspace, disable_progress=no_prog
        )
    except (UnsupportedFormatError, UnsupportedArchError, UnsupportedOSError):
        # CAPA can't extract for some reason, time to give up
        return

    capabilities = capa.main.find_capabilities(rules, extractor, disable_progress=no_prog)

    # put info into metadata section for reports
    meta = capa.loader.collect_metadata([], file_path, file_type, OS_AUTO, rules_path, extractor, capabilities)

    meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)

    # generate a report
    try:
        report = capa.render.vverbose.render(meta, rules, capabilities.matches)
    except RuntimeError:
        # Opt-out when runtime error occurs here.
        # The runtime error excepted is
        # 'unexpected file scope match count: {len(matches)}")\nRuntimeError: unexpected file scope match count: 2\n'
        # This happens when the supplied file isn't fully supported by capa, so an opt-out should occur.
        return

    # build result document to summarise analysis
    doc = rd.ResultDocument.from_capa(meta, rules, capabilities.matches)

    # get results for plugin
    ret = {
        "attack": extract_attack(doc),
        "capabilities": extract_capabilities(doc),
        "mbc": extract_behaviours(doc),
        "report": reformat_report(report),
    }

    # return extracted capabilities, attack techniques, behaviours and plain text report
    return ret


def extract_capabilities(doc: rd) -> list[tuple[str, str]]:
    """Extract CAPA capabilities from CAPA report document.

    :param doc: report document produced by analysis
    :returns: list of capability name and category tuples
    """
    capabilities = []

    for rule in capa.render.utils.capability_rules(doc):
        capabilities.append((rule.meta.name, rule.meta.namespace))

    return capabilities


def extract_attack(doc: rd) -> list[tuple[str, str]]:
    """Extract mitre attack techniques from CAPA report document.

    :param doc: report document produced by analysis
    :returns: list of attack id and attack technique group tuples
    """
    attacks = []

    for rule in capa.render.utils.capability_rules(doc):
        if not rule.meta.attack:
            continue
        for attack in rule.meta.attack:
            attacks.append((attack.id, "::".join(attack.parts)))

    return attacks


def extract_behaviours(doc: rd) -> list[tuple[str, str]]:
    """Extract mitre malware behaviour from CAPA report document.

    :param doc: report document produced by analysis
    :returns: list of behaviour id and behaviour group tuples
    """
    behaviours = []

    for rule in capa.render.utils.capability_rules(doc):
        if not rule.meta.mbc:
            continue
        for mbc in rule.meta.mbc:
            behaviours.append((mbc.id, "::".join(mbc.parts)))

    return behaviours


def reformat_report(report: str) -> str:
    """Remove non-deterministic elements from top of report (e.g file name, timestamp) from the CAPA report.

    :param report: text report produced by CAPA analysis
    :returns: text report with problems removed
    """
    # Remove any trailing spaces before a newline for consistency and ensure that all the other rules work.
    remove_spaces = re.compile("\\s*\n")
    report = remove_spaces.sub("\n", report)

    # remove timestamp and rules path entries, since they change and break test cases
    ts = re.compile("timestamp.+?[0-9]\n", flags=re.DOTALL)
    report = ts.sub("", report)
    rp = re.compile("rules.+?\n", flags=re.DOTALL)
    report = rp.sub("", report)
    xp = re.compile("path.+?\n", flags=re.DOTALL)
    report = xp.sub("", report)

    return report
