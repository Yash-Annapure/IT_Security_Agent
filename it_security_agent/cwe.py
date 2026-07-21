"""Plain-English names and explanations for CWE IDs.

NVD tags each CVE with one or more CWE (Common Weakness Enumeration) IDs saying what
*kind* of flaw it is - but only as bare identifiers like "CWE-79", which tell a reader
nothing on their own. This maps the ones that actually show up on PyPI/npm packages
(the CWE Top 25 plus common library-level flaws) to both a technical name and a
one-line explanation a non-specialist can act on.

Anything not listed here degrades gracefully to the bare ID, which still links out to
cwe.mitre.org - so an unmapped CWE loses the plain-English line, never the report.
"""

# id -> (technical name, plain-English explanation)
NAMES: dict[str, tuple[str, str]] = {
    "CWE-20": ("Improper Input Validation",
               "the software trusts input it should have checked first"),
    "CWE-22": ("Path Traversal",
               "an attacker can reach files outside the folder they're supposed to be limited to"),
    "CWE-77": ("Command Injection",
               "an attacker can get the system to run commands of their choosing"),
    "CWE-78": ("OS Command Injection",
               "an attacker can run operating-system commands on the machine"),
    "CWE-79": ("Cross-site Scripting (XSS)",
               "an attacker can run their own scripts in another user's browser"),
    "CWE-89": ("SQL Injection",
               "an attacker can read or change the database by crafting malicious input"),
    "CWE-94": ("Code Injection",
               "an attacker can get their own code executed by the application"),
    "CWE-120": ("Buffer Overflow",
                "oversized input can overwrite memory, often enabling attacker-controlled code"),
    "CWE-125": ("Out-of-bounds Read",
                "the software reads memory it shouldn't, which can leak sensitive data or crash it"),
    "CWE-190": ("Integer Overflow",
                "a number grows past its maximum and wraps around, producing wrong and unsafe results"),
    "CWE-200": ("Information Disclosure",
                "the software reveals data it should have kept private"),
    "CWE-209": ("Information Exposure Through an Error Message",
                "error messages leak internal details useful to an attacker"),
    "CWE-269": ("Improper Privilege Management",
                "someone can end up with more permissions than they should have"),
    "CWE-287": ("Improper Authentication",
                "the check that you are who you claim to be can be bypassed"),
    "CWE-295": ("Improper Certificate Validation",
                "encrypted connections aren't properly verified, enabling eavesdropping or impersonation"),
    "CWE-306": ("Missing Authentication for Critical Function",
                "something important can be done without logging in at all"),
    "CWE-311": ("Missing Encryption of Sensitive Data",
                "sensitive data is stored or sent without encryption"),
    "CWE-327": ("Use of a Broken or Risky Cryptographic Algorithm",
                "the encryption used is known to be weak and can be broken"),
    "CWE-352": ("Cross-Site Request Forgery (CSRF)",
                "a user can be tricked into performing actions they didn't intend"),
    "CWE-362": ("Race Condition",
                "two things happening at once can leave the system in an unsafe state"),
    "CWE-400": ("Uncontrolled Resource Consumption",
                "an attacker can exhaust memory, CPU or disk and take the service down"),
    "CWE-416": ("Use After Free",
                "memory is used after being released, which can crash the program or let an attacker control it"),
    "CWE-425": ("Direct Request / Forced Browsing",
                "pages meant to be protected can be reached just by knowing the URL"),
    "CWE-434": ("Unrestricted Upload of File with Dangerous Type",
                "an attacker can upload a file that the server will then execute"),
    "CWE-476": ("NULL Pointer Dereference",
                "a missing value causes a crash, typically taking the service down"),
    "CWE-502": ("Deserialization of Untrusted Data",
                "loading attacker-supplied saved data can execute their code"),
    "CWE-522": ("Insufficiently Protected Credentials",
                "passwords or keys are stored or transmitted in a way that's too easy to steal"),
    "CWE-601": ("Open Redirect",
                "the site can be used to bounce users to an attacker's page, aiding phishing"),
    "CWE-611": ("XML External Entity (XXE)",
                "malicious XML can make the server read local files or make network requests"),
    "CWE-640": ("Weak Password Recovery Mechanism",
                "the 'forgot password' flow can be abused to take over someone's account"),
    "CWE-732": ("Incorrect Permission Assignment for Critical Resource",
                "files or settings are readable or writable by people who shouldn't have access"),
    "CWE-787": ("Out-of-bounds Write",
                "the software writes past the end of a buffer, a common route to running attacker code"),
    "CWE-798": ("Use of Hard-coded Credentials",
                "a password or key is baked into the code, so anyone with the code has it"),
    "CWE-835": ("Infinite Loop",
                "input can make the software loop forever and stop responding"),
    "CWE-862": ("Missing Authorization",
                "the software doesn't check whether you're allowed to do what you asked"),
    "CWE-863": ("Incorrect Authorization",
                "the permission check exists but gets the answer wrong"),
    "CWE-918": ("Server-Side Request Forgery (SSRF)",
                "an attacker can make the server send requests to systems it shouldn't reach"),
    "CWE-1321": ("Prototype Pollution",
                 "an attacker can modify shared object defaults, changing behaviour across the app"),
}

MITRE_URL = "https://cwe.mitre.org/data/definitions/{number}.html"


def technical_name(cwe_id: str) -> str:
    """'CWE-79' -> 'Cross-site Scripting (XSS)'. Falls back to the bare ID if unmapped."""
    entry = NAMES.get(cwe_id.upper().strip())
    return entry[0] if entry else cwe_id


def plain_explanation(cwe_id: str) -> str | None:
    """'CWE-79' -> 'an attacker can run their own scripts...'. None if unmapped."""
    entry = NAMES.get(cwe_id.upper().strip())
    return entry[1] if entry else None


def url(cwe_id: str) -> str | None:
    """Link to MITRE's definition, or None if the ID isn't in CWE-<number> form."""
    number = cwe_id.upper().strip().removeprefix("CWE-")
    return MITRE_URL.format(number=number) if number.isdigit() else None
