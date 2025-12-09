"""Azul CAPA plugin.

An Azul plugin that uses Mandiant's CAPA tool to detect capabilities in binaries.
"""

import logging
import os.path
import pathlib
import tempfile

from azul_runner import (
    FV,
    BinaryPlugin,
    Feature,
    FeatureType,
    Job,
    State,
    add_settings,
    cmdline_run,
)

from .utils import CorruptFileError, RuleError, SignatureError, do_capa_processing

# we're doing this so we don't get CAPA's internal logging all over our nice clean stderr
logging.basicConfig(level=logging.CRITICAL)


class AzulPluginMandiantCapa(BinaryPlugin):
    """An Azul plugin that uses FireEye's CAPA tool to detect capabilities in binaries.."""

    VERSION = "2025.12.09"
    SETTINGS = add_settings(
        filter_data_types={
            "content": [
                "executable/windows/",
                "executable/linux/",
                "executable/pe32",
                "executable/dll32",
                "unknown",
            ]
        },
        run_timeout=(int, 0),  # remove the timeout so we can process larger/more complex samples
        filter_max_content_size=(int, 2 * 1024 * 1024),  # File size to process
        ignore_sigs=(str, "no"),  # Use flirt sigs when processing PE files
        see_capa_logging=(str, "no"),  # Enable/Disable CAPA verbose logging.
        terminal_width=(int, 300),  # Width of output terminal for consistent output
        terminal_height=(int, 50),  # Number of lines for output terminal for consistency.
    )
    FEATURES = [
        Feature("capability", desc="Capability identified by Mandiant's CAPA tool", type=FeatureType.String),
        Feature(
            "malware_behavior_catalog",
            desc="Objectives and behaviours from the MITRE Malware Behavior Catalog (MBC)",
            type=FeatureType.String,
        ),
        Feature("attack", desc="Tactics from the MITRE ATT&CK framework", type=FeatureType.String),
    ]

    def __init__(self, *args, **kwargs):
        """Setup plugin with fixed terminal width/height."""
        super().__init__(*args, **kwargs)
        # Docs for rich console settings https://rich.readthedocs.io/en/latest/console.html#environment-variables
        # Fixed terminal width and height for consistent output streams.
        os.environ.setdefault("COLUMNS", str(self.cfg.terminal_width))
        os.environ.setdefault("LINES", str(self.cfg.terminal_height))
        # Override Rich's auto-detection of the console.
        os.environ.setdefault("TTY_COMPATIBLE", "0")
        # Disable animations on console output
        os.environ.setdefault("FORCE_INTERACTIVE", "False")
        os.environ.setdefault("NO_COLOR", "True")

    def execute(self, job: Job) -> dict:
        """Run the plugin."""
        # rules and signatures live here
        # rules will only be used on first run, to generate an optimised version in the cache
        capa_rules_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../capa-rules"))
        capa_sigs_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../capa-sigs"))

        # cached store of rules that is quicker to load
        capa_rules_cache_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../capa-rules-cache"))

        # get data
        data = job.get_data()

        # need to write our sample to disk for CAPA to process it
        with tempfile.NamedTemporaryFile() as file_on_disk:
            buffer = data.read()
            file_on_disk.write(buffer)
            file_on_disk.flush()
            file_on_disk.seek(0)

            # In flare-capa 5.0.0 it seems that the typelib sigs weren't being used to ignore capabilities found in
            # library code.
            # Use ignore_sigs to force azul-capa to behave in the same manner for comparison testing.
            # Works correctly in 5.1.0
            try:
                results = do_capa_processing(
                    pathlib.Path(file_on_disk.name),
                    [pathlib.Path(capa_rules_path)],
                    pathlib.Path(capa_sigs_path),
                    (self.cfg.ignore_sigs == "yes"),
                    cache_dir=pathlib.Path(capa_rules_cache_path),
                    capa_logging=(self.cfg.see_capa_logging == "yes"),
                )
            except (CorruptFileError, RuleError, SignatureError) as e:
                self.logger.warning(str(e))
                raise e
            except UnicodeDecodeError:
                return self.is_malformed("Unicode could not be decoded within PE metadata.")

        # no results, CAPA did not like this file for some reason?
        if not results:
            return State(State.Label.OPT_OUT, message="Capa does not fully support analysis of this file.")

        # store report as text
        if report := results.get("report"):
            self.logger.debug(report)
            self.add_text(report)

        # add features for capabilities
        if capabilities := results.get("capabilities"):
            self.add_feature_values("capability", [FV(x[0], label=x[1]) for x in capabilities])

        # add features for attack
        if attack := results.get("attack"):
            self.add_feature_values("attack", [FV(x[0], label=x[1]) for x in attack])

        # add features for mbc
        if mbc := results.get("mbc"):
            self.add_feature_values("malware_behavior_catalog", [FV(x[0], label=x[1]) for x in mbc])


def main():
    """Plugin command-line entrypoint."""
    cmdline_run(plugin=AzulPluginMandiantCapa)


if __name__ == "__main__":
    main()
