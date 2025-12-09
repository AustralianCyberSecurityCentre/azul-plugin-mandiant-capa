"""Test cases for azul-capa plugin."""

# needed for memory usage profiling
# import pytest
from azul_runner import FV, Event, EventData, JobResult, State, test_template

from azul_plugin_mandiant_capa.main import AzulPluginMandiantCapa


# pytest of everything is ~24s (or ~81s with report_tracemalloc decorators)
class TestMandiantCapa(test_template.TestPlugin):
    """Tests Capa plugin using the current cached ruleset."""

    PLUGIN_TO_TEST = AzulPluginMandiantCapa

    # @pytest.mark.report_tracemalloc
    def test_invalid(self):
        """Test that plugin correctly rejects some files that CAPA doesn't support (well).

        Takes ~2s.
        """
        # upx - 028706fa3cc74c9549f3187b12f6b223cdfc84c6e24e2f6417dbece15ba027f0
        data = self.load_test_file_bytes(
            "028706fa3cc74c9549f3187b12f6b223cdfc84c6e24e2f6417dbece15ba027f0", "Malicious Windows 32EXE, UPX packed."
        )
        result = self.do_execution(data_in=[("content", data)])
        # we OPTOUT of packed samples,
        self.assertJobResult(
            result,
            JobResult(state=State(State.Label.OPT_OUT, message="Capa does not fully support analysis of this file.")),
        )

    def test_packed_sample(self):
        """Test a packed sample can get results through Capa."""
        # vmprotect - 3e753d9ad6c402a4c1827b1a35b58172f2655b242ee0a3b3d354a7ff6b5dd470
        data = self.load_test_file_bytes(
            "3e753d9ad6c402a4c1827b1a35b58172f2655b242ee0a3b3d354a7ff6b5dd470", "Malicious Windows 32EXE."
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="3e753d9ad6c402a4c1827b1a35b58172f2655b242ee0a3b3d354a7ff6b5dd470",
                        data=[
                            EventData(
                                hash="a407ad8f79ebff9d5c2f20cf95f1ddb8042f3757fbf329f4c32bf3e1120e4fe3", label="text"
                            )
                        ],
                        features={
                            "attack": [
                                FV(
                                    "T1027.002",
                                    label="Defense Evasion::Obfuscated Files or Information::Software Packing",
                                )
                            ],
                            "capability": [
                                FV("contain a thread local storage (.tls) section", label="executable/pe/section/tls"),
                                FV("packed with VMProtect", label="anti-analysis/packer/vmprotect"),
                            ],
                            "malware_behavior_catalog": [
                                FV("F0001.010", label="Anti-Static Analysis::Software Packing::VMProtect")
                            ],
                        },
                    )
                ],
                data={
                    "a407ad8f79ebff9d5c2f20cf95f1ddb8042f3757fbf329f4c32bf3e1120e4fe3": b"""md5                     9fc5fa1cd40915612494aec175b74a45
sha1                    27abed4b0bf55adef77aee30a6214ecdf100cae3
sha256                  3e753d9ad6c402a4c1827b1a35b58172f2655b242ee0a3b3d354a7ff6b5dd470
capa version            9.3.1
os                      windows
format                  pe
arch                    i386
analysis                static
extractor               VivisectFeatureExtractor
base address            0x400000
function count          14
library function count  0
total feature count     6799
packed with VMProtect
namespace   anti-analysis/packer/vmprotect
author      william.ballenthin@mandiant.com
scope       file
att&ck      Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]
mbc         Anti-Static Analysis::Software Packing::VMProtect [F0001.010]
references  https://www.pcworld.com/article/2824572/leaked-programming-manual-may-help-criminals-develop-more-atm-malware.html, https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/
or:
  section: .vmp0 @ 0x41C000
  section: .vmp1 @ 0x449000
contain a thread local storage (.tls) section
namespace  executable/pe/section/tls
author     michael.hunhoff@mandiant.com
scope      file
section: .tls @ 0x41A000
(internal) packer file limitation
namespace    internal/limitation/file
author       william.ballenthin@mandiant.com
scope        file
description  This sample appears to be packed.
             Packed samples have often been obfuscated to hide their logic.
             capa cannot handle obfuscation well using static analysis. This means the results may be misleading or incomplete.
             If possible, you should try to unpack this input file before analyzing it with capa.
             Alternatively, run the sample in a supported sandbox and invoke capa against the report to obtain dynamic analysis results.
or:
  match: anti-analysis/packer @ global
    or:
      section: .vmp0 @ 0x41C000
      section: .vmp1 @ 0x449000
"""
                },
            ),
            inspect_data=True,
        )

    # @pytest.mark.report_tracemalloc
    def test_plugx_dll(self):
        """Test plugin on PlugX shellcode loader.

        THOR PlugX shellcode loader 3c5e2a4afe58634f45c48f4e800dc56bae3907dde308ff97740e9cd5684d1c53
        This binary loads and executes a PlugX encoded shellcode payload
        (b5c0db62184325ffbe2b8ef7e6f13f5d5926deac331ef6d542c5fa50144e0280)
        Takes ~11.5s with cached full rules.
        """
        data = self.load_test_file_bytes(
            "3c5e2a4afe58634f45c48f4e800dc56bae3907dde308ff97740e9cd5684d1c53",
            "Malicious Windows 32DLL, PlugX encoded shellcode payload, malware family SOGU.",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="3c5e2a4afe58634f45c48f4e800dc56bae3907dde308ff97740e9cd5684d1c53",
                        data=[
                            EventData(
                                hash="65d7c71024f96912c3eb26e0ae86afde6706c2f8c6fd106e17f4a04681bde9c1", label="text"
                            )
                        ],
                        features={
                            "attack": [
                                FV(
                                    "T1027.005",
                                    label="Defense Evasion::Obfuscated Files or Information::Indicator Removal from Tools",
                                ),
                                FV("T1083", label="Discovery::File and Directory Discovery"),
                                FV("T1129", label="Execution::Shared Modules"),
                            ],
                            "capability": [
                                FV(
                                    "contain obfuscated stackstrings",
                                    label="anti-analysis/obfuscation/string/stackstring",
                                ),
                                FV("get file size", label="host-interaction/file-system/meta"),
                                FV("get thread local storage value", label="host-interaction/process"),
                                FV("link function at runtime on Windows", label="linking/runtime-linking"),
                                FV("link many functions at runtime", label="linking/runtime-linking"),
                                FV("print debug messages", label="host-interaction/log/debug/write-event"),
                            ],
                            "malware_behavior_catalog": [
                                FV(
                                    "B0032.017",
                                    label="Anti-Static Analysis::Executable Code Obfuscation::Stack Strings",
                                ),
                                FV(
                                    "B0032.020",
                                    label="Anti-Static Analysis::Executable Code Obfuscation::Argument Obfuscation",
                                ),
                                FV("E1083", label="Discovery::File and Directory Discovery"),
                            ],
                        },
                    )
                ],
                data={"65d7c71024f96912c3eb26e0ae86afde6706c2f8c6fd106e17f4a04681bde9c1": b""},
            ),
        )

    # @pytest.mark.report_tracemalloc
    def test_shellcode_x86(self):
        """Test plugin on PlugX shellcode.

        THOR PlugX 32bit shellcode - 006f0a1004e960b6a7e7669bf88c240f203a6e5ebb38d92727167741537cae65
        Shellcode was decoded from b5c0db62184325ffbe2b8ef7e6f13f5d5926deac331ef6d542c5fa50144e0280
        Takes ~2.5s with cached full rules.
        """
        data = self.load_test_file_bytes(
            "006f0a1004e960b6a7e7669bf88c240f203a6e5ebb38d92727167741537cae65",
            "Malicious THOR PlugX 32bit shellcode, decoded from b5c0db62184325ffbe2b8ef7e6f13f5d5926deac331ef6d542c5fa50144e0280.",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="006f0a1004e960b6a7e7669bf88c240f203a6e5ebb38d92727167741537cae65",
                        data=[
                            EventData(
                                hash="a4687b436b532b4d6be11a3a29df32ca00a26720263ffa64083d7ed92110d553", label="text"
                            )
                        ],
                        features={
                            "attack": [
                                FV(
                                    "T1027.005",
                                    label="Defense Evasion::Obfuscated Files or Information::Indicator Removal from Tools",
                                ),
                                FV("T1082", label="Discovery::System Information Discovery"),
                                FV("T1129", label="Execution::Shared Modules"),
                            ],
                            "capability": [
                                FV("access PEB ldr_data", label="linking/runtime-linking"),
                                FV(
                                    "contain obfuscated stackstrings",
                                    label="anti-analysis/obfuscation/string/stackstring",
                                ),
                                FV("get number of processors", label="host-interaction/hardware/cpu"),
                                FV("resolve function by hash", label="linking/runtime-linking"),
                            ],
                            "malware_behavior_catalog": [
                                FV(
                                    "B0032.017",
                                    label="Anti-Static Analysis::Executable Code Obfuscation::Stack Strings",
                                ),
                                FV(
                                    "B0032.020",
                                    label="Anti-Static Analysis::Executable Code Obfuscation::Argument Obfuscation",
                                ),
                            ],
                        },
                    )
                ],
                data={"a4687b436b532b4d6be11a3a29df32ca00a26720263ffa64083d7ed92110d553": b""},
            ),
        )

    # @pytest.mark.report_tracemalloc
    def test_shellcode_x64(self):
        """Test plugin on Metasploit x64 shellcode.

        Windows/x64 - Metasploit windows/x64/powershell_reverse_tcp
        built with msfvenom -p windows/x64/powershell_reverse_tcp -o shellcode.bin
        a1cb4905d8db07e87ff5ab1bccc26b0de422e3a214f498383d9670223c25c9fc
        Takes ~1.5s with cached full ruleset.
        """
        data = self.load_test_file_bytes(
            "a1cb4905d8db07e87ff5ab1bccc26b0de422e3a214f498383d9670223c25c9fc",
            "Windows/x64 - Metasploit windows/x64/powershell_reverse_tcp, built with msfvenom -p windows/x64/powershell_reverse_tcp -o shellcode.bin",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="a1cb4905d8db07e87ff5ab1bccc26b0de422e3a214f498383d9670223c25c9fc",
                        data=[
                            EventData(
                                hash="a97077e7874708d0cd118b3175eb11e8b3cad9208e970429e9ef598b076391bd", label="text"
                            )
                        ],
                        features={
                            "attack": [FV("T1129", label="Execution::Shared Modules")],
                            "capability": [FV("access PEB ldr_data", label="linking/runtime-linking")],
                        },
                    )
                ],
                data={"a97077e7874708d0cd118b3175eb11e8b3cad9208e970429e9ef598b076391bd": b""},
            ),
        )

    # @pytest.mark.report_tracemalloc
    def test_dotnet(self):
        """Test plugin on simple .NET application.

        bd5bf1c7c8f6dea328ce04aa5e7690a5a0e9ef3d4c9b011db6e923d3c40ae566
        .NET console Hello World application.
        Takes <1s with cached full ruleset.
        """
        data = self.load_test_file_bytes(
            "bd5bf1c7c8f6dea328ce04aa5e7690a5a0e9ef3d4c9b011db6e923d3c40ae566",
            "Basic .NET console Hello World application.",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="bd5bf1c7c8f6dea328ce04aa5e7690a5a0e9ef3d4c9b011db6e923d3c40ae566",
                        data=[
                            EventData(
                                hash="f88904f4bf9b43509a4e1e03da9a49276675211da5b5a47a38469ac220b73111", label="text"
                            )
                        ],
                        features={
                            "capability": [
                                FV("compiled to the .NET platform", label="runtime/dotnet"),
                                FV("manipulate console buffer", label="host-interaction/console"),
                            ],
                            "malware_behavior_catalog": [FV("C0033", label="Operating System::Console")],
                        },
                    )
                ],
                data={"f88904f4bf9b43509a4e1e03da9a49276675211da5b5a47a38469ac220b73111": b""},
            ),
        )

    # @pytest.mark.report_tracemalloc
    def test_elf(self):
        """Test plugin on ELF sample.

        294b8db1f2702b60fb2e42fdc50c2cee6a5046112da9a5703a548a4fa50477bc
        Vermillion Strike (Cobalt Strike written for Linux )
        Takes ~10s with cached full ruleset.
        """
        data = self.load_test_file_bytes(
            "294b8db1f2702b60fb2e42fdc50c2cee6a5046112da9a5703a548a4fa50477bc",
            "Malicious ELF64, CobaltStrikeBeacon called Vermillion Strike.",
        )
        result = self.do_execution(data_in=[("content", data)])

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="294b8db1f2702b60fb2e42fdc50c2cee6a5046112da9a5703a548a4fa50477bc",
                        data=[
                            EventData(
                                hash="44c61cdf9d5fe4af533b340af498715907ef4f5ce3acff96734cf68f848cb2cc", label="text"
                            )
                        ],
                        features={
                            "attack": [
                                FV("T1016", label="Discovery::System Network Configuration Discovery"),
                                FV("T1027", label="Defense Evasion::Obfuscated Files or Information"),
                                FV("T1033", label="Discovery::System Owner/User Discovery"),
                                FV("T1082", label="Discovery::System Information Discovery"),
                                FV("T1083", label="Discovery::File and Directory Discovery"),
                            ],
                            "capability": [
                                FV(
                                    "communicate with kernel module via Netlink socket on Linux",
                                    label="host-interaction/kernel",
                                ),
                                FV("create UDP socket", label="communication/socket/udp/send"),
                                FV("create process on Linux", label="host-interaction/process/create"),
                                FV("create raw socket", label="communication/socket"),
                                FV("create semaphore on Linux", label="host-interaction/mutex"),
                                FV("create thread", label="host-interaction/thread/create"),
                                FV("encode data using XOR", label="data-manipulation/encoding/xor"),
                                FV("encrypt data using RC4 PRGA", label="data-manipulation/encryption/rc4"),
                                FV("enumerate files on Linux", label="host-interaction/file-system/files/list"),
                                FV("execute syscall", label="anti-analysis"),
                                FV("get current PID on Linux", label="host-interaction/process"),
                                FV("get current user on Linux", label="host-interaction/session"),
                                FV("get hostname", label="host-interaction/os/hostname"),
                                FV("get kernel version", label="host-interaction/os/version"),
                                FV("get networking interfaces", label="host-interaction/network/interface"),
                                FV("get password database entry on Linux", label="host-interaction/session"),
                                FV("lock semaphore on Linux", label="host-interaction/mutex"),
                                FV("read file on Linux", label="host-interaction/file-system/read"),
                                FV("receive data", label="communication"),
                                FV("receive data on socket", label="communication/socket/receive"),
                                FV("resolve DNS", label="communication/dns"),
                                FV("send data", label="communication"),
                                FV("send data on socket", label="communication/socket/send"),
                                FV("set current directory", label="host-interaction/file-system"),
                                FV("set socket configuration", label="communication/socket"),
                                FV("unlock semaphore on Linux", label="host-interaction/mutex"),
                                FV("write file on Linux", label="host-interaction/file-system/write"),
                            ],
                            "malware_behavior_catalog": [
                                FV("B0030.001", label="Command and Control::C2 Communication::Send Data"),
                                FV("B0030.002", label="Command and Control::C2 Communication::Receive Data"),
                                FV("C0001.001", label="Communication::Socket Communication::Set Socket Config"),
                                FV("C0001.003", label="Communication::Socket Communication::Create Socket"),
                                FV("C0001.006", label="Communication::Socket Communication::Receive Data"),
                                FV("C0001.007", label="Communication::Socket Communication::Send Data"),
                                FV("C0001.010", label="Communication::Socket Communication::Create UDP Socket"),
                                FV("C0011.001", label="Communication::DNS Communication::Resolve"),
                                FV("C0017", label="Process::Create Process"),
                                FV("C0021.004", label="Cryptography::Generate Pseudo-random Sequence::RC4 PRGA"),
                                FV("C0026.002", label="Data::Encode Data::XOR"),
                                FV("C0027.009", label="Cryptography::Encrypt Data::RC4"),
                                FV("C0038", label="Process::Create Thread"),
                                FV("C0051", label="File System::Read File"),
                                FV("C0052", label="File System::Writes File"),
                                FV(
                                    "E1027.m02",
                                    label="Defense Evasion::Obfuscated Files or Information::Encoding-Standard Algorithm",
                                ),
                                FV("E1082", label="Discovery::System Information Discovery"),
                                FV("E1083", label="Discovery::File and Directory Discovery"),
                            ],
                        },
                    )
                ],
                data={"44c61cdf9d5fe4af533b340af498715907ef4f5ce3acff96734cf68f848cb2cc": b""},
            ),
        )

    def test_pe_with_hex_section(self):
        """Test a PE that has sections that are labelled as hex values which mandiant can't handle."""
        data = self.load_test_file_bytes(
            "bd8b088f2460047d293fcbab99fdbea51cef334c18bdd40e403376f1dd3a5e91",
            "Malicious Windows DLL32, sections that are labelled as hex values, malware family CobaltStrikeBeacon",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.COMPLETED_WITH_ERRORS, message="Unicode could not be decoded within PE metadata."
                ),
                events=[
                    Event(
                        sha256="bd8b088f2460047d293fcbab99fdbea51cef334c18bdd40e403376f1dd3a5e91",
                        features={"malformed": [FV("Unicode could not be decoded within PE metadata.")]},
                    )
                ],
            ),
        )
