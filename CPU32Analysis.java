/* ###
 * SPDX-License-Identifier: Apache-2.0
 * © Brad Ackerman.
 */

//Mark up CPU32 stuff. (WIP)
//@author Brad Ackerman <brad@facefault.org>
//@category 68000 Scripts
//@keybinding
//@menupath
//@toolbar

import org.apache.commons.lang3.StringUtils;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

public class CPU32Analysis extends GhidraScript {
	final long MBAR_ADDRESS = 0x3ff00;
	// our only current language ID
	final String CPU32 = "68000:BE:32:CPU32";

	// MCR struct data
	private class SIM40Info {
		public int offset;
		public int length;
		public String mnemonic;
		public String description;

		public SIM40Info(int offset, int length, String mnemonic, String description) {
			this.offset = offset;
			this.length = length;
			this.mnemonic = mnemonic;
			this.description = description;
		}
	}
	
	private class ChipSelectInfo {
		public long baseAddress = 0;
		public long mask = 0;
		public long sizeBytes = 0;
		boolean isValid = false;
		public String toString() {
			return String.format("BA: %8x  Mask: %s  Size: %4d kiB  Valid: %b", this.baseAddress, StringUtils.leftPad(Long.toBinaryString(this.mask), 24, '0'), this.sizeBytes >> 10, this.isValid);
		}
	}
	
	private ChipSelectInfo[] csInfo;

	final private SIM40Info[] sim40StructData = { new SIM40Info(0x000, 2, "MCR", "Module Confiugration Register"),
			new SIM40Info(0x004, 2, "SYNCR", "Clock Synthesizer Control Register"),
			new SIM40Info(0x006, 1, "AVR", "Autovector Register"),
			new SIM40Info(0x007, 1, "RSR", "Reset Status Register"),
			new SIM40Info(0x011, 1, "PORTA", "Port A Data Register"),
			new SIM40Info(0x013, 1, "DDRA", "Port A Pin Data Direction Register"),
			new SIM40Info(0x015, 1, "PPARA1", "Port A Pin Assignment Register 1"),
			new SIM40Info(0x017, 1, "PPARA2", "Port A Pin Assignment Register 2"),
			new SIM40Info(0x019, 1, "PORTB", "Port B Data Register"),
			new SIM40Info(0x019, 1, "PORTB1", "Port B Data Register"),
			new SIM40Info(0x01D, 1, "DDRB", "Port B Pin Data Direction Register"),
			new SIM40Info(0x01F, 1, "PPARB", "Port B Pin Assignment Register 1"),
			new SIM40Info(0x020, 1, "SWIV", "Software Interrupt Vector Register"),
			new SIM40Info(0x021, 1, "SYPCR", "System Protection Control Register"),
			new SIM40Info(0x022, 2, "PICR", "Periodic Interrupt Control Register"),
			new SIM40Info(0x024, 2, "PITR", "Periodic Interrupt Timer Register"),
			new SIM40Info(0x027, 1, "SWSR", "Software Service Register"),
			new SIM40Info(0x040, 2, "AM1CS0", "Address Mask 1 CS0"),
			new SIM40Info(0x042, 2, "AM2CS0", "Address Mask 2 CS0"),
			new SIM40Info(0x044, 2, "BA1CS0", "Base Address 1 CS0"),
			new SIM40Info(0x046, 2, "BA2CS0", "Base Address 2 CS0"),
			new SIM40Info(0x048, 2, "AM1CS1", "Address Mask 1 CS1"),
			new SIM40Info(0x04A, 2, "AM2CS1", "Address Mask 2 CS1"),
			new SIM40Info(0x04C, 2, "BA1CS1", "Base Address 1 CS1"),
			new SIM40Info(0x04E, 2, "BA2CS1", "Base Address 2 CS1"),
			new SIM40Info(0x050, 2, "AM1CS2", "Address Mask 1 CS2"),
			new SIM40Info(0x052, 2, "AM2CS2", "Address Mask 2 CS2"),
			new SIM40Info(0x054, 2, "BA1CS2", "Base Address 1 CS2"),
			new SIM40Info(0x056, 2, "BA2CS2", "Base Address 2 CS2"),
			new SIM40Info(0x058, 2, "AM1CS3", "Address Mask 1 CS3"),
			new SIM40Info(0x05A, 2, "AM2CS3", "Address Mask 2 CS3"),
			new SIM40Info(0x05C, 2, "BA1CS3", "Base Address 1 CS3"),
			new SIM40Info(0x05E, 2, "BA2CS3", "Base Address 2 CS3") };
	
	protected String getMnemonicAnnotation(int offset, long val) {
		for (SIM40Info inf : sim40StructData) {
			if (offset == inf.offset) {
				String mnemonic = inf.mnemonic;
				StringBuilder sb = new StringBuilder();
				if (mnemonic.startsWith("AM")) {
					// This code assumes it's a long to AM1CS*.
					long maskVal = val >> 8;
					long width = Long.bitCount(maskVal) + 8;
					int csIndex = Integer.parseInt(mnemonic.substring(5));
					this.csInfo[csIndex].mask = maskVal;
					this.csInfo[csIndex].sizeBytes = 1 << width;
					sb.append(mnemonic.substring(3));
					sb.append(" has block size 2^");
					sb.append(width);
					sb.append(" and mask\n0b");
					sb.append(StringUtils.leftPad(Long.toBinaryString(maskVal), 24, '0'));
					sb.append(".\n");
					long fcm = (val >> 4) & 0b1111;
					sb.append("FC3..FC0 values: 0b");
					sb.append(Long.toString(fcm, 2));
					sb.append(".\n");
					long dd = (val >> 2) & 0b11;
					sb.append("DD1..DD0 values: 0b");
					sb.append(Long.toString(dd, 2));
					sb.append(".\n");
					long ps = (val >> 2) & 0b11;
					sb.append("PS1..PS0 values: 0b");
					sb.append(Long.toString(ps, 2));
					sb.append(".\n");
					return sb.toString();
				} else if (mnemonic.startsWith("BA")) {
					// This code assumes it's a long to BA1CS*.
					// clear the lower 8 bits
					long baTop = val & 0xffff_ff00;
					int csIndex = Integer.parseInt(mnemonic.substring(5));
					this.csInfo[csIndex].baseAddress = baTop;
					sb.append(mnemonic.substring(3));
					sb.append(" has base address 0x");
					sb.append(StringUtils.leftPad(Long.toHexString(baTop), 8, '0'));
					sb.append(". ");
					// to do stuff in between
					boolean isValid = (val & 0b1) == 0b1;
					sb.append(mnemonic.substring(3));
					if (isValid) {
						sb.append(" is ");
					} else {
						sb.append(" is not ");
					}
					sb.append("valid.");
					this.csInfo[csIndex].isValid = isValid;
					return sb.toString();
				}
				switch (mnemonic) {
				case "MCR":
					// TODO
					return "MCR";
				}
				// Annotation is for this item.
				println("TODO: annotate " + inf.mnemonic);
				return "This is a test.";
			}
		}
		return null;
	}

	/// Return the register that contains the value written to
	/// MBAR, or null if not here.
	protected Register registerHasMbar(Instruction ins) {
		Register register = null;
		Address address = null;
		int numOps = ins.getNumOperands();
		for (int i = 0; i < numOps; i++) {
			RefType rtype = ins.getOperandRefType(i);
			Object[] ops = ins.getOpObjects(i);
			// assuming we don't care about multi-object operands
			if (rtype.isRead() && ops[0] instanceof Register) {
				register = (Register) ops[0];
			} else if (rtype.isWrite() && ops[0] instanceof Address) {
				address = (Address) ops[0];
			}
		}
		if (address != null && address.getOffset() == MBAR_ADDRESS) {
			return register;
		}
		return null;
	}

	/// Return the value written to the specified register.
	protected Address valueInRegister(Instruction ins, Register r) {
		Address address = null;
		boolean matchRegister = false;
		int numOps = ins.getNumOperands();
		for (int i = 0; i < numOps; i++) {
			RefType rtype = ins.getOperandRefType(i);
			Object[] ops = ins.getOpObjects(i);
			// assuming we don't care about multi-object operands
			if (rtype.isWrite() && ops[0] instanceof Register) {
				Register candidateRegister = (Register) ops[0];
				if (r.equals(candidateRegister)) {
					matchRegister = true;
				}
			} else if (rtype.isData() && ops[0] instanceof Scalar) {
				Scalar s = (Scalar) ops[0];
				// There really should be a better way to do this.
				String sString = s.toString(16, true, true, "0x", "");
				address = getAddressFactory().getAddress(sString);
			}
		}
		if (matchRegister) {
			return address;
		}
		return null;
	}

	protected DataType createSim40Struct() {
		DataTypeManager dtm = currentProgram.getDataTypeManager();

		StructureDataType simDt = new StructureDataType("sim40", 0, dtm);
		for (int i = 0; i < sim40StructData.length; i++) {
			SIM40Info member = sim40StructData[i];
			DataType memberType = member.length == 2 ? UnsignedShortDataType.dataType : UnsignedCharDataType.dataType;
			simDt.insertAtOffset(member.offset, memberType, member.length, member.mnemonic, member.description);
		}
		dtm.addDataType(simDt, null);
		return simDt;
	}

	protected void annotateSim40(Address sim40Base) {
		int maxOffset = 0x5e;
		Address sim40End = sim40Base.add(maxOffset+1);
		Instruction ins = getFirstInstruction();
		while (ins != null) {
			Address validAddress = null;
			long writtenValue = 0;
			int numOps = ins.getNumOperands();
			for (int i = 0; i < numOps; i++) {
				Object[] ops = ins.getOpObjects(i);
				RefType rt = ins.getOperandRefType(i);
				if (rt != null && rt.isData() && ops[0] instanceof Scalar) {
					Scalar s = (Scalar) ops[0];
					writtenValue = s.getUnsignedValue();
				} else if (rt != null && rt.isWrite() && ops[0] instanceof Address) {
					Address a = (Address) ops[0];
					// Replace with check for the sim40 block we added, if I can figure out how.
					if (a.compareTo(sim40Base) > 0 && a.compareTo(sim40End) < 0) {
						// Address is within the SIM40 area.
						validAddress = a;
					}
				}
			}
			if (validAddress != null && writtenValue != 0) {
				long offset = validAddress.subtract(sim40Base);
				String annotation = getMnemonicAnnotation((int)offset, writtenValue);
				if (annotation != null) {
					setPlateComment(ins.getAddress(), annotation);

				}
			}
			ins = ins.getNext();
		}
	}

	@Override
	protected void run() throws Exception {
		// reset instance vars -- is this object reused?
		this.csInfo = new ChipSelectInfo[4];
		for (int i = 0; i < 4; i++) {
			this.csInfo[i] = new ChipSelectInfo();
		}
		if (currentProgram == null) {
			Msg.error(this, "Current program is null");
		} else {
			String lang = currentProgram.getLanguageID().getIdAsString();
			if (!(lang.equals(CPU32))) {
				Msg.showError(this, null, "Invalid architecture", "'" + lang + "'");
				return;
			}
		}
		Address zeroAddr = currentProgram.getImageBase();
		MemoryBlock rom = getMemoryBlock(zeroAddr);
		createData(zeroAddr, PointerDataType.dataType);
		setEOLComment(zeroAddr, "Inital SSP on reset");
		Data initialPc = createData(zeroAddr.add(4), PointerDataType.dataType);
		initialPc.setComment(CodeUnit.EOL_COMMENT, "Inital PC on reset");
		// TODO: program tree name?
		rom.setName("rom");
		rom.setWrite(false);
		rom.setExecute(true);
		// Set new memory block length to the nearest (size of ROM) kB containing the
		// starting
		// stack pointer.
		long ramStart = rom.getEnd().add(1).getOffset();
		long ramEnd = 0;
		long blockSizeIncrement = rom.getSize();
		long initialSsp = getInt(zeroAddr);
		while (ramEnd < initialSsp) {
			ramEnd += blockSizeIncrement;
		}
		long blockLength = ramEnd - ramStart;
		MemoryBlock ram = createMemoryBlock("ram", rom.getEnd().add(1), null, blockLength, false);
		ram.setWrite(true);
		ram.setExecute(true);
		Address ipcAddr = (Address) initialPc.getValue();
		disassemble(ipcAddr);
		createFunction(ipcAddr, "entypoint");
		Function ep = getFunctionAt(ipcAddr);
		ep.setName("entrypoint", SourceType.DEFAULT);
		ep.setNoReturn(true);

		// Find the location of MCR by naïvely checking entry point function
		Address newAddr = ep.getEntryPoint();
		Instruction inst = getInstructionAt(newAddr);
		Register reg = null;
		do {
			reg = registerHasMbar(inst);
			if (reg == null) {
				inst = inst.getNext();
			}
		} while (inst != null && reg == null);
		if (reg == null) {
			Msg.showError(this, null, "Unable to parse", "Can't find MBAR source register");
			return;
		}
		Address mbarAddress = null;
		do {
			inst = inst.getPrevious();
			mbarAddress = valueInRegister(inst, reg);
		} while (inst != null && mbarAddress == null);
		if (mbarAddress == null) {
			Msg.showError(this, null, "Unable to parse", "Can't find MBAR address");
			return;
		}
		// The low bit of the MBAR is set to 1, which is the "valid" bit.
		// The actual SIM40 region starts at 0.
		// TODO: AS8..AS0 need to be dealt with if set.
		mbarAddress = mbarAddress.subtract(1);
		print("Found MBAR address: " + mbarAddress.toString());
		MemoryBlock sim = createMemoryBlock("sim40", mbarAddress, null, 0x80l, false);
		sim.setWrite(true);
		sim.setVolatile(true);
		DataType simDt = createSim40Struct();
		createData(mbarAddress, simDt);
		// Create the other SIM40 module register blocks.
		MemoryBlock timerModules = createMemoryBlock("timerModules", mbarAddress.add(0x600), null, 0x80, false);
		MemoryBlock serialPorts = createMemoryBlock("serialPorts", mbarAddress.add(0x700), null, 0x22, false);
		MemoryBlock dma = createMemoryBlock("dma", mbarAddress.add(0x780), null, 0x40, false);
		timerModules.setVolatile(true);
		timerModules.setWrite(true);
		serialPorts.setVolatile(true);
		serialPorts.setWrite(true);
		dma.setVolatile(true);
		dma.setWrite(true);
		
		annotateSim40(mbarAddress);
		for (int i = 0; i < 4; i++) {
			println("CS" + i + ": " + this.csInfo[i].toString());
		}
	}
}
