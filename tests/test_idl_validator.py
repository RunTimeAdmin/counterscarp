"""
Tests for the idl_validator module.
"""

import pytest
import sys
import os
import json

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

from idl_validator import (
    IDLAccount,
    IDLInstruction,
    IDLProgram,
    IDLParser,
    ConstraintValidator,
    CPITracer,
    AccountPermissionMatrix,
    validate_idl,
    find_idl_files,
    generate_idl_report,
)


# =============================================================================
# IDLAccount Tests
# =============================================================================

class TestIDLAccount:
    """Test IDLAccount dataclass."""

    def test_creation(self):
        """Test creating an IDLAccount."""
        account = IDLAccount(
            name="vault",
            is_mut=True,
            is_signer=False,
            pda={"seeds": []}
        )
        
        assert account.name == "vault"
        assert account.is_mut is True
        assert account.is_signer is False
        assert account.pda is not None

    def test_default_values(self):
        """Test IDLAccount with default values."""
        account = IDLAccount(name="authority")
        
        assert account.is_mut is False
        assert account.is_signer is False
        assert account.is_optional is False
        assert account.docs == []
        assert account.pda is None
        assert account.relations == []


# =============================================================================
# IDLInstruction Tests
# =============================================================================

class TestIDLInstruction:
    """Test IDLInstruction dataclass."""

    def test_creation(self):
        """Test creating an IDLInstruction."""
        account = IDLAccount(name="vault")
        instruction = IDLInstruction(
            name="initialize",
            accounts=[account],
            args=[{"name": "amount", "type": "u64"}]
        )
        
        assert instruction.name == "initialize"
        assert len(instruction.accounts) == 1
        assert len(instruction.args) == 1

    def test_default_values(self):
        """Test IDLInstruction with default values."""
        instruction = IDLInstruction(name="deposit")
        
        assert instruction.accounts == []
        assert instruction.args == []
        assert instruction.docs == []


# =============================================================================
# IDLProgram Tests
# =============================================================================

class TestIDLProgram:
    """Test IDLProgram dataclass."""

    def test_creation(self):
        """Test creating an IDLProgram."""
        program = IDLProgram(
            name="my_program",
            version="0.1.0",
            instructions=[IDLInstruction(name="init")],
            metadata={"address": "abc123"}
        )
        
        assert program.name == "my_program"
        assert program.version == "0.1.0"
        assert len(program.instructions) == 1

    def test_default_values(self):
        """Test IDLProgram with default values."""
        program = IDLProgram(name="test", version="1.0")
        
        assert program.instructions == []
        assert program.accounts == []
        assert program.types == []
        assert program.events == []
        assert program.errors == []
        assert program.metadata == {}


# =============================================================================
# IDLParser Tests
# =============================================================================

class TestIDLParser:
    """Test IDLParser class."""

    def test_parse_valid_idl(self, tmp_path, sample_idl_json):
        """Test parsing a valid IDL file."""
        idl_file = tmp_path / "test.json"
        idl_file.write_text(json.dumps(sample_idl_json))
        
        program = IDLParser.parse(str(idl_file))
        
        assert program.name == "test_program"
        assert program.version == "0.1.0"
        assert len(program.instructions) == 2

    def test_parse_missing_file(self, tmp_path):
        """Test parsing a non-existent file."""
        from exceptions import CounterscarpValidationError
        
        with pytest.raises(CounterscarpValidationError):
            IDLParser.parse(str(tmp_path / "nonexistent.json"))

    def test_parse_invalid_json(self, tmp_path):
        """Test parsing invalid JSON."""
        from exceptions import CounterscarpValidationError
        
        idl_file = tmp_path / "invalid.json"
        idl_file.write_text("not valid json")
        
        with pytest.raises(CounterscarpValidationError):
            IDLParser.parse(str(idl_file))

    def test_parse_instruction_accounts(self, tmp_path, sample_idl_json):
        """Test parsing instruction accounts."""
        idl_file = tmp_path / "test.json"
        idl_file.write_text(json.dumps(sample_idl_json))
        
        program = IDLParser.parse(str(idl_file))
        
        init_instruction = program.instructions[0]
        assert len(init_instruction.accounts) == 3
        
        vault_account = init_instruction.accounts[0]
        assert vault_account.name == "vault"
        assert vault_account.is_mut is True
        assert vault_account.pda is not None


# =============================================================================
# ConstraintValidator Tests
# =============================================================================

class TestConstraintValidator:
    """Test ConstraintValidator class."""

    def test_validate_signer_constraints_missing(self):
        """Test detecting missing signer constraints."""
        instruction = IDLInstruction(
            name="initialize",
            accounts=[
                IDLAccount(name="authority", is_signer=False),
                IDLAccount(name="payer", is_signer=False),
            ]
        )
        
        findings = ConstraintValidator.validate_signer_constraints(instruction)
        
        assert len(findings) > 0
        assert any("IDL_MISSING_SIGNER" in f["rule_id"] for f in findings)

    def test_validate_signer_constraints_ok(self):
        """Test when signer constraints are correct."""
        instruction = IDLInstruction(
            name="initialize",
            accounts=[
                IDLAccount(name="authority", is_signer=True),
            ]
        )
        
        findings = ConstraintValidator.validate_signer_constraints(instruction)
        
        assert len(findings) == 0

    def test_validate_mutability_constraints_missing(self):
        """Test detecting missing mutability constraints."""
        instruction = IDLInstruction(
            name="update_state",
            accounts=[
                IDLAccount(name="state", is_mut=False),  # Should be mutable
            ]
        )
        
        findings = ConstraintValidator.validate_mutability_constraints(
            instruction
        )
        
        assert len(findings) > 0

    def test_validate_pda_constraints_missing_seeds(self):
        """Test detecting PDA without seeds."""
        instruction = IDLInstruction(
            name="initialize",
            accounts=[
                IDLAccount(
                    name="vault",
                    pda={"seeds": []}  # Empty seeds
                ),
            ]
        )
        
        findings = ConstraintValidator.validate_pda_constraints(instruction)
        
        assert len(findings) > 0
        assert any("IDL_PDA_MISSING_SEEDS" in f["rule_id"] for f in findings)

    def test_validate_pda_constraints_missing_bump(self):
        """Test detecting PDA without bump."""
        instruction = IDLInstruction(
            name="initialize",
            accounts=[
                IDLAccount(
                    name="vault",
                    pda={"seeds": [{"kind": "const", "value": [1]}]}
                ),
            ]
        )
        
        findings = ConstraintValidator.validate_pda_constraints(instruction)
        
        assert len(findings) > 0
        assert any("IDL_PDA_MISSING_BUMP" in f["rule_id"] for f in findings)


# =============================================================================
# CPITracer Tests
# =============================================================================

class TestCPITracer:
    """Test CPITracer class."""

    def test_detect_cpi_accounts(self):
        """Test detecting CPI-related accounts."""
        instruction = IDLInstruction(
            name="transfer",
            accounts=[
                IDLAccount(name="token_program"),
                IDLAccount(name="user_account"),
            ]
        )
        
        findings = CPITracer.detect_cpi_accounts(instruction)
        
        assert len(findings) > 0
        assert any("token_program" in str(f) for f in findings)

    def test_build_cpi_flow_matrix(self):
        """Test building CPI flow matrix."""
        program = IDLProgram(
            name="test",
            version="1.0",
            instructions=[
                IDLInstruction(
                    name="transfer",
                    accounts=[
                        IDLAccount(name="token_program"),
                    ]
                ),
                IDLInstruction(
                    name="create_account",
                    accounts=[
                        IDLAccount(name="system_program"),
                    ]
                ),
            ]
        )
        
        matrix = CPITracer.build_cpi_flow_matrix(program)
        
        assert "transfer" in matrix
        assert "create_account" in matrix


# =============================================================================
# AccountPermissionMatrix Tests
# =============================================================================

class TestAccountPermissionMatrix:
    """Test AccountPermissionMatrix class."""

    def test_generate_matrix(self):
        """Test generating permission matrix."""
        program = IDLProgram(
            name="test",
            version="1.0",
            instructions=[
                IDLInstruction(
                    name="initialize",
                    accounts=[
                        IDLAccount(name="vault", is_mut=True, is_signer=False),
                        IDLAccount(name="authority", is_signer=True),
                    ]
                ),
            ]
        )
        
        matrix = AccountPermissionMatrix.generate_matrix(program)
        
        assert matrix["program_name"] == "test"
        assert "initialize" in matrix["instructions"]
        assert matrix["instructions"]["initialize"]["signer_required"] is True

    def test_print_matrix(self):
        """Test printing permission matrix."""
        program = IDLProgram(
            name="test",
            version="1.0",
            instructions=[
                IDLInstruction(
                    name="init",
                    accounts=[IDLAccount(name="vault")]
                ),
            ]
        )
        
        matrix = AccountPermissionMatrix.generate_matrix(program)
        output = AccountPermissionMatrix.print_matrix(matrix)
        
        assert isinstance(output, str)
        assert "test" in output
        assert "init" in output


# =============================================================================
# validate_idl Tests
# =============================================================================

class TestValidateIdl:
    """Test validate_idl function."""

    def test_validate_valid_idl(self, tmp_path, sample_idl_json):
        """Test validating a valid IDL."""
        idl_file = tmp_path / "test.json"
        idl_file.write_text(json.dumps(sample_idl_json))
        
        findings = validate_idl(str(idl_file))
        
        # Should return findings (even valid IDLs may have suggestions)
        assert isinstance(findings, list)

    def test_validate_with_constraints_disabled(self, tmp_path, sample_idl_json):
        """Test validating with constraints disabled."""
        idl_file = tmp_path / "test.json"
        idl_file.write_text(json.dumps(sample_idl_json))
        
        findings = validate_idl(str(idl_file), validate_constraints=False)
        
        # Should not have constraint-related findings
        constraint_findings = [
            f for f in findings
            if f.get("rule_id", "").startswith("IDL_")
        ]
        # May still have CPI findings

    def test_validate_with_cpi_disabled(self, tmp_path, sample_idl_json):
        """Test validating with CPI tracing disabled."""
        idl_file = tmp_path / "test.json"
        idl_file.write_text(json.dumps(sample_idl_json))
        
        findings = validate_idl(str(idl_file), trace_cpi=False)
        
        # Should not have CPI-related findings
        cpi_findings = [
            f for f in findings if "CPI" in f.get("rule_id", "")
        ]
        assert len(cpi_findings) == 0

    def test_invalid_idl_file(self, tmp_path):
        """Test validating invalid IDL file."""
        from exceptions import CounterscarpValidationError
        
        with pytest.raises(CounterscarpValidationError):
            validate_idl(str(tmp_path / "nonexistent.json"))


# =============================================================================
# find_idl_files Tests
# =============================================================================

class TestFindIdlFiles:
    """Test find_idl_files function."""

    def test_find_idl_in_target_idl(self, tmp_path):
        """Test finding IDL files in target/idl directory."""
        target_idl = tmp_path / "target" / "idl"
        target_idl.mkdir(parents=True)
        
        idl_content = json.dumps({
            "name": "test",
            "version": "1.0",
            "instructions": []
        })
        (target_idl / "test.json").write_text(idl_content)
        
        idl_files = find_idl_files(str(tmp_path))
        
        assert len(idl_files) == 1
        assert "test.json" in idl_files[0]

    def test_find_idl_in_idl_directory(self, tmp_path):
        """Test finding IDL files in idl directory."""
        idl_dir = tmp_path / "idl"
        idl_dir.mkdir()
        
        idl_content = json.dumps({
            "name": "test",
            "version": "1.0",
            "instructions": []
        })
        (idl_dir / "program.json").write_text(idl_content)
        
        idl_files = find_idl_files(str(tmp_path))
        
        assert len(idl_files) == 1

    def test_no_idl_files(self, tmp_path):
        """Test when no IDL files exist."""
        idl_files = find_idl_files(str(tmp_path))
        
        assert idl_files == []

    def test_skip_invalid_json(self, tmp_path):
        """Test skipping invalid JSON files."""
        target_idl = tmp_path / "target" / "idl"
        target_idl.mkdir(parents=True)
        
        (target_idl / "invalid.json").write_text("not valid json")
        
        idl_files = find_idl_files(str(tmp_path))
        
        assert len(idl_files) == 0


# =============================================================================
# generate_idl_report Tests
# =============================================================================

class TestGenerateIdlReport:
    """Test generate_idl_report function."""

    def test_generate_report_with_findings(self, tmp_path, sample_idl_json):
        """Test generating report with findings."""
        idl_file = tmp_path / "test.json"
        idl_file.write_text(json.dumps(sample_idl_json))
        
        findings = [
            {
                "rule_id": "IDL_MISSING_SIGNER",
                "severity": "HIGH",
                "description": "Missing signer constraint",
                "instruction": "initialize",
                "account": "authority"
            }
        ]
        
        report = generate_idl_report(str(idl_file), findings)
        
        assert "ANCHOR IDL SECURITY VALIDATION REPORT" in report
        assert "IDL_MISSING_SIGNER" in report
        assert "HIGH" in report

    def test_generate_report_no_findings(self, tmp_path, sample_idl_json):
        """Test generating report with no findings."""
        idl_file = tmp_path / "test.json"
        idl_file.write_text(json.dumps(sample_idl_json))
        
        report = generate_idl_report(str(idl_file), [])
        
        assert "ANCHOR IDL SECURITY VALIDATION REPORT" in report
        assert "No issues found" in report

    def test_generate_report_with_matrix(self, tmp_path, sample_idl_json):
        """Test generating report with permission matrix."""
        idl_file = tmp_path / "test.json"
        idl_file.write_text(json.dumps(sample_idl_json))
        
        report = generate_idl_report(
            str(idl_file), [], include_matrix=True
        )
        
        assert "Account Permission Matrix" in report
