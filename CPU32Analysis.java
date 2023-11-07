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

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
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
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class CPU32Analysis extends GhidraScript {
	final long MBAR_ADDRESS = 0x3ff00;
	// our only current language ID
	final String CPU32 = "68000:BE:32:CPU32";

	// SIM40 struct data
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
		boolean writeProtect = false;
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

	private class DMAInfo {
		public int ch1Offset, length;
		public String mnemonic, name;
		public DMAInfo(int ch1Offset, int length, String mnemonic, String name) {
			this.ch1Offset = ch1Offset;
			this.mnemonic = mnemonic;
			this.name = name;
		}
	}

	final private DMAInfo[] dmaRegisters = {
			new DMAInfo(0x780, 2, "MCR", "Module Configuration Register"),
			new DMAInfo(0x784, 2, "IR", "Interrupt Register"),
			new DMAInfo(0x788, 2, "CCR", "Channel Control Register"),
			new DMAInfo(0x78A, 1, "CSR", "Channel Status Register"),
			new DMAInfo(0x78B, 1, "FCR", "Function Code Register"),
			new DMAInfo(0x78C, 2, "SARM", "Source Address Register (MSBs)"),
			new DMAInfo(0x78E, 2, "SARL", "Source Address Register (LSBs)"),
			new DMAInfo(0x790, 2, "DARM", "Destination Address Register (MSBs)"),
			new DMAInfo(0x792, 2, "DARL", "Destination Address Register (LSBs)"),
			new DMAInfo(0x794, 2, "BTCM", "Byte Transfer Counter (MSBs)"),
			new DMAInfo(0x796, 2, "BTCL", "Byte Transfer Counter (LSBs)")
	};

	protected static String leftPadBinary(long val, int fieldWidth) {
		return StringUtils.leftPad(Long.toBinaryString(val), fieldWidth, '0');
	}

	protected static boolean bit(long val, int bitNumber) {
		return ((val >> bitNumber) & 0b1) == 0b1;
	}

	protected String getSim40MnemonicAnnotation(int offset, long val) {
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
					sb.append(mnemonic.substring(3))
						.append(" has block size 2^")
						.append(width)
						.append(" and mask\n0b")
						.append(leftPadBinary(maskVal, 24))
						.append(".\n");
					long fcm = (val >> 4) & 0b1111;
					sb.append("FCM3..FCM0 values: 0b")
						.append(leftPadBinary(fcm, 4))
						.append(".\n");
					long dd = (val >> 2) & 0b11;
					sb.append("DD1..DD0 values: 0b")
						.append(leftPadBinary(dd, 2))
						.append(" (")
						.append(dd)
						.append(" DSACK wait state");
					if (dd != 1) {
						sb.append("s");
					}
					sb.append(").\n");
					long ps = (val >> 2) & 0b11;
					sb.append("PS1..PS0 values: 0b")
						.append(leftPadBinary(ps, 2));
					switch ((int) ps) {
					case 0:
						sb.append(" (reserved (32-bit DMA))");
						break;
					case 1:
						sb.append(" (16-bit port)");
						break;
					case 2:
						sb.append(" (8-bit port)");
						break;
					default: // 3
						sb.append(" (external /DSACK response)");
					}
					sb.append(".\n");
					return sb.toString();
				} else if (mnemonic.startsWith("BA")) {
					// This code assumes it's a long to BA1CS*.
					// clear the lower 8 bits
					long baTop = val & 0xffff_ff00;
					int csIndex = Integer.parseInt(mnemonic.substring(5));
					this.csInfo[csIndex].baseAddress = baTop;
					sb.append(mnemonic.substring(3))
						.append(" has base address 0x")
						.append(StringUtils.leftPad(Long.toHexString(baTop), 8, '0'))
						.append(".\n");
					long bfc = (val >> 4) & 0b1111;
					sb.append("BFC3..BFC0 values: 0b")
						.append(leftPadBinary(bfc, 4))
						.append(".\n");
					boolean writeProtect = ((val >> 3) & 0b1) == 0b1;
					this.csInfo[csIndex].writeProtect = writeProtect;
					sb.append("Write protect: ")
						.append(writeProtect)
						.append(".\n");
					boolean fastTermination = ((val >> 2) & 0b1) == 0b1;
					sb.append("Fast termination enabled: ")
						.append(fastTermination)
						.append(".\n");
					boolean noCpu = ((val >> 1) & 0b1) == 0b1;
					sb.append("Suppress on CPU space access: ")
						.append(noCpu)
						.append(".\n");
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
					long frz = (val >> 13) & 0b11;
					sb.append("FRZ1..FRZ0: 0b")
						.append(leftPadBinary(frz, 2))
						.append(".\n");
					long firq = (val >> 12) & 0b1;
					sb.append("FIRQ: 0b")
						.append(leftPadBinary(firq, 1))
						.append(".\n  ");
					if (firq == 0b1) {
						sb.append("(Port B: 7 IRQ, autovector, no external CS\n)");
					} else {
						sb.append("(Port B: 4 IRQ, no autovector, 4 external CS\n)");
					}
					long shen = (val >> 8) & 0b11;
					sb.append("SHEN1..SHEN0: 0b")
						.append(leftPadBinary(shen, 2))
						.append(".\n  ");
					switch ((int)shen) {
					case 0:
						sb.append("(Show cycles disabled,\n   external arbitration enabled");
						break;
					case 1:
						sb.append("Show cycles enabled,\n   external arbitration disabled");
						break;
					default: // 2/3
						sb.append("Show cycles enabled,\n   external arbitration enabled");
					}
					sb.append(")\n");
					boolean supv = ((val >> 7) & 0b1) == 0b1;
					sb.append("Supervisor restrictions enforced: ")
						.append(supv)
						.append(".\n");
					long iarb = (val & 0b1111);
					sb.append("IARB3..IARB0: 0b")
						.append(leftPadBinary(iarb, 4));
					if (iarb == 0) {
						sb.append(" (SIM40 interrupts disabled)");
					}
					sb.append(".\n");
					return sb.toString();
				case "AVR":
					sb.append("AV7..AV1: 0b")
						.append(leftPadBinary(val, 7))
						.append("\n");
					return sb.toString();
				case "RSR":
					return "RSR writes have no effect.";
				case "SWSR":
					return "Software watchdog servicing sequence written.";
				case "PPARA1":
					sb.append("Port A assignments: 0b")
						.append(leftPadBinary(val, 8))
						.append("\nSet: IO pin\nCleared: A31..A24\n");
					return sb.toString();
				case "PPARB":
					sb.append("Port B assignments: 0b")
						.append(leftPadBinary(val, 8))
						.append("\nSet: /IRQ or /CS\nCleared: IO pin (/CS if MCR FIRQ is 0)\n");
					return sb.toString();
				case "PORTA":
				case "PORTB":
					// It's obvious.
					return null;
				}
				// Mnemonic not yet annotated.
				println("TODO: annotate " + inf.mnemonic);
				return "TODO: annotate " + inf.mnemonic;
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


	/**
	 * Annotate SIM40 writes with their function.
	 * @param sim40Base The base address of the SIM40 block.
	 */
	protected void annotateSim40(Address sim40Base) {
		int maxOffset = 0x5e;
		Address sim40End = sim40Base.add(maxOffset+1);
		Instruction ins = getFirstInstruction();
		while (ins != null) {
			Address validAddress = null;
			long writtenValue = 0;
			boolean foundWrittenValue = false;
			int numOps = ins.getNumOperands();
			for (int i = 0; i < numOps; i++) {
				Object[] ops = ins.getOpObjects(i);
				RefType rt = ins.getOperandRefType(i);
				if (rt != null && rt.isData() && ops[0] instanceof Scalar) {
					Scalar s = (Scalar) ops[0];
					writtenValue = s.getUnsignedValue();
					foundWrittenValue = true;
				} else if (rt != null && rt.isWrite() && ops[0] instanceof Address) {
					Address a = (Address) ops[0];
					// Replace with check for the sim40 block we added, if I can figure out how.
					if (a.compareTo(sim40Base) >= 0 && a.compareTo(sim40End) < 0) {
						// Address is within the SIM40 area.
						validAddress = a;
					}
				}
			}
			if (validAddress != null && foundWrittenValue) {
				long offset = validAddress.subtract(sim40Base);
				String annotation = getSim40MnemonicAnnotation((int)offset, writtenValue);
				if (annotation != null) {
					setPlateComment(ins.getAddress(), annotation);
				}
			}
			ins = ins.getNext();
		}
	}

	/**
	 * Rename the symbol (usually DAT_xxxx) at the specified address. If no
	 * symbol is present, create one.
	 * @param address The address to rename.
	 * @param name The desired name of the address.
	 * @throws Exception if there's already a symbol
	 * with that name, or possibly other reasons.
	 *
	 */
	protected Symbol renameOrCreateSymbol(Address address, String name) throws Exception {
		Symbol maybeSymbol = getSymbolAt(address);
		if (maybeSymbol == null) {
			maybeSymbol = createLabel(address, name, true);
		} else {
			maybeSymbol.setName(name, SourceType.USER_DEFINED);
		}
		return maybeSymbol;
	}

	/**
	 * Annotate the serial ports' register locations in memory.
	 * @param sim40Base The base of the SIM40 register block in memory.
	 * @throws Exception
	 */
	protected void annotateSerialPorts(Address sim40Base) throws Exception {
		Map<Integer, String> registers = new HashMap<Integer, String>();
		// TODO: more
		registers.put(0x711, "SRA_CSRA");
		registers.put(0x719, "SRB_CSRB");
		registers.put(0x713, "RBA_TBA");
		registers.put(0x71B, "RBB_TBB");
		for (Map.Entry<Integer, String> r : registers.entrySet()) {
			renameOrCreateSymbol(sim40Base.add(r.getKey()), r.getValue());
		}
	}

	protected void annotateDma(Address sim40Base) throws Exception {
		final int ch2Offset = 0x20;
		for (DMAInfo reg : dmaRegisters) {
			Address ch1Address = sim40Base.add(reg.ch1Offset);
			Address ch2Address = ch1Address.add(ch2Offset);
			renameOrCreateSymbol(ch1Address, "DMA_" + reg.mnemonic + "1");
			setEOLComment(ch1Address, "DMA " + reg.name + " 1");
			renameOrCreateSymbol(ch2Address, "DMA_" + reg.mnemonic + "2");
			setEOLComment(ch2Address, "DMA " + reg.name + " 2");
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
		// Get AddressFactory and default address space for use below.
		AddressFactory af = getAddressFactory();
		AddressSpace defaultAddressSpace = af.getDefaultAddressSpace();

		Address zeroAddr = currentProgram.getImageBase();
		createData(zeroAddr, PointerDataType.dataType);
		setEOLComment(zeroAddr, "Inital SSP on reset");
		Data initialPc = createData(zeroAddr.add(4), PointerDataType.dataType);
		initialPc.setComment(CodeUnit.EOL_COMMENT, "Inital PC on reset");

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
		Address mbarValue = null;
		do {
			inst = inst.getPrevious();
			mbarValue = valueInRegister(inst, reg);
		} while (inst != null && mbarValue == null);
		if (mbarValue == null) {
			Msg.showError(this, null, "Unable to parse", "Can't find MBAR value");
			return;
		}
		// The low bit of the MBAR is set to 1, which is the "valid" bit.
		// The actual SIM40 region starts at 0.
		// inst is the instruction that loads the value to be stored in the MBAR.
		long mbarValueLong = mbarValue.getOffset();
		long baseAddress = mbarValueLong & 0xffff_f000;
		long addressSpaceMasking = mbarValueLong >> 1 & 0x1ff;
		boolean isValid = (mbarValueLong & 0x1) == 0x1;
		StringBuilder annotation = new StringBuilder();
		annotation.append("This value (0x")
			.append(Long.toHexString(mbarValueLong))
			.append(") will be stored to the MBAR (0x3FF00).")
			.append("\nSIM40 base address: 0x" + Long.toHexString(baseAddress))
			.append("\nAS8..0: 0b")
			.append(StringUtils.leftPad(Long.toHexString(addressSpaceMasking), 8, '0'))
			.append("\nValid: ")
			.append(isValid);
		setPlateComment(inst.getAddress(), annotation.toString());
		Symbol mbarData = getSymbolAt(defaultAddressSpace.getAddress(MBAR_ADDRESS));
		mbarData.setName("MBAR", SourceType.USER_DEFINED);
		Address sim40Base = af.getAddress(defaultAddressSpace.getSpaceID(), baseAddress);
		MemoryBlock sim = createMemoryBlock("sim40", sim40Base, null, 0x80l, false);
		sim.setWrite(true);
		sim.setVolatile(true);
		DataType simDt = createSim40Struct();
		createData(sim40Base, simDt);
		// Create the other SIM40 module register blocks.
		MemoryBlock timerModules = createMemoryBlock("timerModules", sim40Base.add(0x600), null, 0x80, false);
		MemoryBlock serialPorts = createMemoryBlock("serialPorts", sim40Base.add(0x700), null, 0x22, false);
		MemoryBlock dma = createMemoryBlock("dma", sim40Base.add(0x780), null, 0x40, false);
		timerModules.setVolatile(true);
		timerModules.setWrite(true);
		serialPorts.setVolatile(true);
		serialPorts.setWrite(true);
		dma.setVolatile(true);
		dma.setWrite(true);

		annotateSim40(sim40Base);
		// Create memory blocks cs0..cs3.
		for (int i = 0; i < 4; i++) {
			ChipSelectInfo inf = this.csInfo[i];
			if (i == 0) {
				// The boot ROM is always at CS0.
				// TODO: What if it's mapped to a non-zero base address?
				// Also TODO: overlapping ranges, noncontiguous set AM bits.
				MemoryBlock rom = getMemoryBlock(zeroAddr);
				rom.setName("cs0");
				rom.setWrite(false);
				rom.setExecute(true);
				rom.setComment("Boot ROM");
			} else {
				MemoryBlock csMem = createMemoryBlock("cs"+i, defaultAddressSpace.getAddress(inf.baseAddress), null, inf.sizeBytes, false);
				csMem.setWrite(!inf.writeProtect);
			}
			println("CS" + i + ": " + this.csInfo[i].toString());
		}
		annotateSerialPorts(sim40Base);
		annotateDma(sim40Base);
	}
}
