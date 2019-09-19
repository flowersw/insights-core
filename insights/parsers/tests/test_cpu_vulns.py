from insights.parsers import SkipException
from insights.tests import context_wrap
from insights.parsers import cpu_vulns
from insights.parsers.cpu_vulns import CpuVulnsMeltdown
from insights.parsers.cpu_vulns import CpuVulnsSpectreV1
from insights.parsers.cpu_vulns import CpuVulnsSpectreV2
from insights.parsers.cpu_vulns import CpuVulnsSpecStoreBypass
from insights.parsers.cpu_vulns import CpuVulnsSmt
from insights.parsers.cpu_vulns import CpuVulnsMds
import pytest
import doctest

INPUT_MELTDOWN = """
Mitigation: PTI
""".strip()

INPUT_SPECTRE_V1 = """
Mitigation: Load fences
""".strip()

INPUT_SPECTRE_V2_RHEL_7_1 = """
Mitigation: Full generic retpoline, IBPB: conditional, IBRS_FW, STIBP: conditional, RSB filling
""".strip()

INPUT_SPECTRE_V2_RHEL_7 = """
Vulnerable: Retpoline without IBPB
""".strip()

INPUT_SPECTRE_V2_RHEL_6 = """
Mitigation: IBRS (kernel)
""".strip()

INPUT_SPEC_STORE_BYPASS = """
Mitigation: Speculative Store Bypass disabled
""".strip()

INPUT_SPEC_STORE_BYPASS_2 = """
Not affected
""".strip()

INPUT_SPEC_STORE_BYPASS_3 = """
Vulnerable
""".strip()

INPUT_SMT = """
Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT vulnerable
""".strip()

# This could occur if you've not updated to the latest intel-microcode package or if Intel has not released new microcode for your processor. You'll see the following in this situation:
INPUT_MDS = """
Vulnerable: Clear CPU buffers attempted, no microcode; SMT vulnerable
""".strip()

# Processors that aren't vulnerable to MDS will report the following:
INPUT_MDS_2 = """
Not affected
""".strip()

# Processors that have Hyper-Threading support enabled will indicate that SMT is vulnerable:
INPUT_MDS_3 = """
Mitigation: Clear CPU buffers; SMT vulnerable
""".strip()

# The file will contain the following contents for processors that do not support Intel Hyper-Threading or where Hyper-Threading has been disabled:
INPUT_MDS_4 = """
Mitigation: Clear CPU buffers; SMT disabled
""".strip()

# The kernel is unable to reliably determine whether Hyper-Threading is enabled when running in a virtual environment. Updated host kernel packages, updated host qemu packages with proper configuration to pass through the host CPU type to the guest, and updated guest kernel packages will show the following status inside of the virtual environment:
INPUT_MDS_5 = """
Mitigation: Clear CPU buffers; SMT Host state unknown
""".strip()


# CpuVulnsMeltdown
def test_cpu_vulns_meltdown():
    spectre = CpuVulnsMeltdown(context_wrap(INPUT_MELTDOWN,
        path='/tmp/meltdown'))
    assert spectre.value == INPUT_MELTDOWN


def test_cpu_vulns_meltdown_exp1():
    """
    Here test the examples cause expections
    """
    with pytest.raises(SkipException) as sc1:
        CpuVulnsMeltdown(context_wrap(''))
    assert "Input content is empty" in str(sc1)


# CpuVulnsSpecStoreBypass
def test_cpu_vulns_spec_store_bypass():
    spectre = CpuVulnsSpecStoreBypass(context_wrap(INPUT_SPEC_STORE_BYPASS,
        path='/tmp/spec_store_bypass'))
    assert spectre.value == INPUT_SPEC_STORE_BYPASS


def test_cpu_vulns_spec_store_bypass_2():
    spectre = CpuVulnsSpecStoreBypass(context_wrap(INPUT_SPEC_STORE_BYPASS_2,
        path='/tmp/spec_store_bypass'))
    assert spectre.value == INPUT_SPEC_STORE_BYPASS_2


def test_cpu_vulns_spec_store_bypass_3():
    spectre = CpuVulnsSpecStoreBypass(context_wrap(INPUT_SPEC_STORE_BYPASS_3,
        path='/tmp/spec_store_bypass'))
    assert spectre.value == INPUT_SPEC_STORE_BYPASS_3


def test_cpu_vulns_spec_store_bypass_exp1():
    """
    Here test the examples cause expections
    """
    with pytest.raises(SkipException) as sc1:
        CpuVulnsSpecStoreBypass(context_wrap(''))
    assert "Input content is empty" in str(sc1)


# CpuVulnsSmt
def test_cpu_vulns_smt():
    spectre = CpuVulnsSmt(context_wrap(INPUT_SMT,
        path='/tmp/l1tf'))
    assert spectre.value == INPUT_SMT


def test_cpu_vulns_smt_exp1():
    """
    Here test the examples cause expections
    """
    with pytest.raises(SkipException) as sc1:
        CpuVulnsSmt(context_wrap(''))
    assert "Input content is empty" in str(sc1)


# CpuVulnsMds
def test_cpu_vulns_mds():
    spectre = CpuVulnsMds(context_wrap(INPUT_MDS,
        path='/tmp/mds'))
    assert spectre.value == INPUT_MDS


def test_cpu_vulns_mds_2():
    spectre = CpuVulnsMds(context_wrap(INPUT_MDS_2,
        path='/tmp/mds'))
    assert spectre.value == INPUT_MDS_2


def test_cpu_vulns_mds_3():
    spectre = CpuVulnsMds(context_wrap(INPUT_MDS_3,
        path='/tmp/mds'))
    assert spectre.value == INPUT_MDS_3


def test_cpu_vulns_mds_4():
    spectre = CpuVulnsMds(context_wrap(INPUT_MDS_4,
        path='/tmp/mds'))
    assert spectre.value == INPUT_MDS_4


def test_cpu_vulns_mds_exp1():
    """
    Here test the examples cause expections
    """
    with pytest.raises(SkipException) as sc1:
        CpuVulnsMds(context_wrap(''))
    assert "Input content is empty" in str(sc1)


# CpuVulnsSpectreV1
def test_cpu_vulns_spectre_v1():
    spectre = CpuVulnsSpectreV1(context_wrap(INPUT_SPECTRE_V1,
        path='/tmp/spectre_v1'))
    assert spectre.value == INPUT_SPECTRE_V1


def test_cpu_vulns_spectre_v1_exp1():
    """
    Here test the examples cause expections
    """
    with pytest.raises(SkipException) as sc1:
        CpuVulnsSpectreV1(context_wrap(''))
    assert "Input content is empty" in str(sc1)


# CpuVulnsSpectreV2
def test_cpu_vulns_spectre_v2_rhel7():
    """
    Here test the examples for spectre_v2
    """
    spectre = CpuVulnsSpectreV2(context_wrap(INPUT_SPECTRE_V2_RHEL_7,
        path='/tmp/spectre_v2'))
    assert spectre.value == INPUT_SPECTRE_V2_RHEL_7


def test_cpu_vulns_spectre_v2_rhel6():
    """
    Here test the examples for spectre_v2
    """
    spectre = CpuVulnsSpectreV2(context_wrap(INPUT_SPECTRE_V2_RHEL_6,
        path='/tmp/spectre_v2'))
    assert spectre.value == INPUT_SPECTRE_V2_RHEL_6


def test_cpu_vulns_spectre_v2_exp1():
    """
    Here test the examples cause expections
    """
    with pytest.raises(SkipException) as sc1:
        CpuVulnsSpectreV2(context_wrap(''))
    assert "Input content is empty" in str(sc1)


def test_cpu_vulns_documentation():
    """
    Here we test the examples in the documentation automatically using doctest.
    We set up an environment which is similar to what a rule writer might see -
    a '/sys/devices/system/cpu/vulnerabilities/spectre_v1' output that has been
    passed in as a parameter to the rule declaration.
    """
    env = {
        'sp_v1': CpuVulnsSpectreV1(context_wrap(INPUT_SPECTRE_V1,
            path='/tmp/spectre_v1')),
        'sp_v2': CpuVulnsSpectreV2(context_wrap(INPUT_SPECTRE_V2_RHEL_7,
            path='/tmp/spectre_v2')),
        'md': CpuVulnsMeltdown(context_wrap(INPUT_MELTDOWN,
            path='/tmp/meltdown')),
        'ssb': CpuVulnsSpecStoreBypass(context_wrap(INPUT_SPEC_STORE_BYPASS,
            path='/tmp/spec_store_bypass')),
        'smt': CpuVulnsSmt(context_wrap(INPUT_SMT,
            path='/tmp/l1tf')),
        'mds': CpuVulnsMds(context_wrap(INPUT_MDS,
            path='/tmp/mds'))}

    failed, total = doctest.testmod(cpu_vulns, globs=env)
    assert failed == 0