import re

PCR_VALUE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED = (0, 7, 11)
OPTIONAL = {2: "peripheral_firmware", 3: "eeprom_configuration"}


class PolicyError(ValueError):
    pass


def lowered(values):
    return sorted({str(v).lower() for v in values if PCR_VALUE.match(str(v).lower())})


class Policy:
    def __init__(self, document):
        document = document if isinstance(document, dict) else {}
        self.allowed = {
            0: lowered(e.get("pcr0", "") for e in document.get("firmware", []) if isinstance(e, dict)),
            7: lowered([(document.get("secure_boot") or {}).get("pcr7", "")] + [e.get("pcr7", "") for e in document.get("secure_boot_all", [])]),
            11: lowered(e.get("pcr11", "") for e in document.get("versions", []) if isinstance(e, dict)),
        }
        for number, section in OPTIONAL.items():
            values = lowered(e.get(f"pcr{number}", "") for e in document.get(section, []) if isinstance(e, dict))
            if values:
                self.allowed[number] = values
        self.images = {
            str(e.get("pcr11", "")).lower(): str(e.get("version")) for e in document.get("versions", []) if isinstance(e, dict)
        }

    def check(self, pcrs):
        for number in REQUIRED:
            if not self.allowed[number]:
                raise PolicyError(f"the policy accepts no value for PCR {number}")
        for number, allowed in self.allowed.items():
            value = str(pcrs.get(str(number), pcrs.get(number, ""))).lower()
            if value not in allowed:
                raise PolicyError(f"PCR {number} is {value[:16] or 'missing'}, not one the policy accepts")
        return self.images.get(str(pcrs.get("11", pcrs.get(11, ""))).lower())
