//package v5;

import java.util.ArrayList;

public class TEAEngineV5 {

	// private fields
	private ArrayList<Integer> inputBlocks = new ArrayList<>(); // even number of pairs of 32bit values
	private int[] keys = new int[] { 0x1310914, 0x1310916, 0x13107FD, 0x1301D30 };

	private int iv[] = new int[] { 0xE8E804, 0x2b21a3aa }; // 32 bits of Initialization Vector
	private int DELTA = 0x9e3779b9;
	private boolean isCBC = false;
	private ArrayList<Integer> encryptedOutput = new ArrayList<>();
	private ArrayList<Integer> decryptedOutput = new ArrayList<>();
	private ArrayList<Long> encryptedLong = new ArrayList<>();
	private ArrayList<Long> decryptedLong = new ArrayList<>();
	private ArrayList<Long> inputLong = new ArrayList<>();
	private ArrayList<char[]> encryptedCharArr = new ArrayList<>();
	private ArrayList<char[]> decryptedCharArr = new ArrayList<>();
	private ArrayList<int[]> pointList = new ArrayList<>();
	private ArrayList<int[]> encPointList = new ArrayList<>();
	private ArrayList<int[]> decpointList = new ArrayList<>();
	private ArrayList<int[]> inpointList = new ArrayList<>();
	public int[] profile = new int[64];

	// Constructor
	public TEAEngineV5(ArrayList<Integer> inputBlocks, int[] keys, int[] iv, boolean isCBC) {
		this.setInputBlocks(inputBlocks);
		this.setKeys(keys);
		this.setIv(iv);
		this.setCBC(isCBC);

		// create list of longs from half block input
		for (int i = 0; i < this.getInputBlocks().size(); i += 2) {
			int l = this.getInputBlocks().get(i);
			int r = this.getInputBlocks().get(i + 1);
			this.getInputLong().add(this.combineToLong(l, r));
		}

		for (int i = 0; i < 64; i++) {
			profile[i] = (int) (Math.random() * 256);
			//profile[i] = i;
		}

	}

	public TEAEngineV5() {

	}

	public void encrypt() {

		// clear previous output ArrayList
		this.getEncryptedOutput().clear();

		// encrypt with current parameters
		for (int i = 0; i < (this.getInputLong().size()); i++) {

			int Lblock = this.splitFromLong(this.getInputLong().get(i), true);
			int Rblock = this.splitFromLong(this.getInputLong().get(i), false);

			// CBC
			if (this.isCBC() && (i == 0)) {
				Lblock ^= iv[0];
				Rblock ^= iv[1];
			} else if (this.isCBC()) {

				int lastL = Integer.parseUnsignedInt(
						new String(this.splitFromcharArr(this.getEncryptedCharArr().get(i - 1), true)), 2);
				int lastR = Integer.parseUnsignedInt(
						new String(this.splitFromcharArr(this.getEncryptedCharArr().get(i - 1), false)), 2);
				Lblock ^= lastL;
				Rblock ^= lastR;
			}

			encryptBlock(Lblock, Rblock);

			// performing XOR with IV and <<5 =BELOW=
			// TODO change to splitfromLong this.getEncryptedLong(i)
			int lastL = this.getEncryptedOutput().get(this.getEncryptedOutput().size() - 2);
			int lastR = this.getEncryptedOutput().get(this.getEncryptedOutput().size() - 1);

			// long from last two halfblocks
			long ecLong = this.combineToLong(lastL, lastR);

			// long into array then circular <<5
			char[] ecLongArr = ((String.format("%64s", (Long.toBinaryString(ecLong)))).replace(" ", "0")).toCharArray();
			ecLongArr = this.rotate(ecLongArr, 5);

			// IV + i as char[]
			char[] ivPlusIArr = ((String.format("%64s", (Long.toBinaryString((this.combineToLong(iv[0], iv[1])) + i))))
					.replace(" ", "0")).toCharArray();

			// XOR with IV+I
			char[] encCharArr = this.XOR(ecLongArr, ivPlusIArr);

			// add to encryptedCharArr list
			this.getEncryptedCharArr().add(encCharArr);

			// make halfblocks
			String strNLB = (new String(this.splitFromcharArr(encCharArr, true)));
			int nLB = Integer.parseUnsignedInt(strNLB, 2);
			int nRB = Integer.parseUnsignedInt((new String(this.splitFromcharArr(encCharArr, false))), 2);

			this.getEncryptedOutput().set(this.getEncryptedOutput().size() - 2, nLB);
			this.getEncryptedOutput().set(this.getEncryptedOutput().size() - 1, nRB);
			// this.getEncryptedOutput().add(nLB);
			// this.getEncryptedOutput().add(nRB);

			// add result to encrypted longs list
			// this.getEncryptedLong().add(ecLong);
		}

	}

	protected void encryptBlock(int Lblock, int Rblock) {

		int sum = 0;
		// Encrypt
		for (int i = 0; i < 32; i++) {
			sum += this.getDELTA();
			Lblock += ((Rblock << 4) + this.getKeys()[0]) ^ (Rblock + sum) ^ ((Rblock >> 5) + this.getKeys()[1]);
			Rblock += ((Lblock << 4) + this.getKeys()[2]) ^ (Lblock + sum) ^ ((Lblock >> 5) + this.getKeys()[3]);
		}

		// add Encrypted halfBlocks to Output List
		this.getEncryptedOutput().add(Lblock);
		this.getEncryptedOutput().add(Rblock);

		// half blocks as long
		// long ecLong = this.combineToLong(Lblock, Rblock);

		// System.out.println("Output List Content: \t" + this.getEncryptedOutput());

	}

	// print out the current HexValues of the EncyptedOutput List
	public String printEncryptedOutput() {
		String result = "";

		for (int i = 0; i < this.getEncryptedOutput().size(); i++) {
			result += (Integer.toHexString(this.getEncryptedOutput().get(i)) + "\n");
		}
		return result;
	}

	public String printEncryptedCharArr() {
		String result = "";

		for (int i = 0; i < this.getEncryptedCharArr().size(); i++) {
			result += new String(this.getEncryptedCharArr().get(i)) + "\n";
		}
		return result;
	}

	public String printDecryptedCharArr() {
		String result = "";

		for (int i = 0; i < this.getDecryptedCharArr().size(); i++) {
			result += new String(this.getDecryptedCharArr().get(i)) + "\n";
		}
		return result;
	}

	// print out the current HexValues of the DecryptedOutput List
	public String printDecryptedOutput() {
		String result = "";
		for (int i = 0; i < this.getDecryptedOutput().size(); i++) {
			result += (Integer.toHexString(this.getDecryptedOutput().get(i)) + "\n");
		}

		return result;
	}

	// print out the current HexValues of the InputBlock List
	public String printInputBlocks() {
		String result = "";
		for (int i = 0; i < this.getInputBlocks().size(); i++) {
			result += Integer.toHexString(this.getInputBlocks().get(i)) + "\n";
		}
		return result;
	}

	public String printInputLongs() {

		String result = "";

		for (Long l : this.getInputLong()) {
			result += Long.toHexString(l) + "\n";
		}

		return result;
	}

	public String printEncryptedLongs() {

		String result = "";

		for (Long l : this.getEncryptedLong()) {
			result += Long.toHexString(l) + "\n";
		}

		return result;
	}

	public String printDecryptedLongs() {

		String result = "";

		for (Long l : this.getDecryptedLong()) {
			result += Long.toHexString(l) + "\n";
		}

		return result;
	}

	public void decrypt() {
		// clear previous list of Decrypted Output
		this.getDecryptedOutput().clear();

		// encrypt with current parameters
		for (int i = 0; i < (this.getEncryptedCharArr().size()); i++) {

			// encryptedLong XOR with
			char[] ecChars = this.getEncryptedCharArr().get(i);

			// IV + i as char[]
			char[] ivPlusIArr = ((String.format("%64s", (Long.toBinaryString((this.combineToLong(iv[0], iv[1])) + i))))
					.replace(" ", "0")).toCharArray();

			// XOR with IV+I
			char[] decCharArr = this.XOR(ecChars, ivPlusIArr);

			decCharArr = this.rotate(decCharArr, -5);

			// add to encryptedCharArr list
			// this.getDecryptedCharArr().add(decCharArr);

			// make half blocks
			int nLB = Integer.parseUnsignedInt((new String(this.splitFromcharArr(decCharArr, true))), 2);
			int nRB = Integer.parseUnsignedInt((new String(this.splitFromcharArr(decCharArr, false))), 2);

			decryptBlock(nLB, nRB, i);
		}
	}

	protected void decryptBlock(int Lblock, int Rblock, int roundNum) {

		// Decrypt block with given parameters
		int sum2 = this.getDELTA() << 5;
		for (int i = 0; i < 32; i++) {
			Rblock -= ((Lblock << 4) + keys[2]) ^ (Lblock + sum2) ^ ((Lblock >> 5) + keys[3]);
			Lblock -= ((Rblock << 4) + keys[0]) ^ (Rblock + sum2) ^ ((Rblock >> 5) + keys[1]);
			sum2 -= this.getDELTA();
		}

		// check for CBC
		if (this.isCBC() && (roundNum == 0)) {
			Lblock ^= iv[0];
			Rblock ^= iv[1];
		} else if (this.isCBC()) {
			int lastL = Integer.parseUnsignedInt(
					new String(this.splitFromcharArr(this.getEncryptedCharArr().get(roundNum - 1), true)), 2);
			int lastR = Integer.parseUnsignedInt(
					new String(this.splitFromcharArr(this.getEncryptedCharArr().get(roundNum - 1), false)), 2);
			Lblock ^= lastL;
			Rblock ^= lastR;
		}

		this.getDecryptedOutput().add(Lblock);
		this.getDecryptedOutput().add(Rblock);

		long decOutputLong = (this.combineToLong(Lblock, Rblock));
		char[] decOutputLongArr = ((String.format("%64s", (Long.toBinaryString(decOutputLong)))).replace(" ", "0"))
				.toCharArray();
		this.getDecryptedCharArr().add(decOutputLongArr);

	}

	// Access & Mutate
	protected ArrayList<Integer> getInputBlocks() {
		return inputBlocks;
	}

	public void setInputBlocks(ArrayList<Integer> inputBlocks) {
		this.inputBlocks = inputBlocks;
	}

	public int[] getKeys() {
		return keys;
	}

	public void setKeys(int[] key2) {
		this.keys = key2;
	}

	public int[] getIv() {
		return iv;
	}

	public void setIv(int[] iv) {
		this.iv = iv;
	}

	public int getDELTA() {
		return DELTA;
	}

	public boolean isCBC() {
		return isCBC;
	}

	public void setCBC(boolean isCBC) {
		this.isCBC = isCBC;
	}

	protected ArrayList<Integer> getEncryptedOutput() {
		return encryptedOutput;
	}

	protected ArrayList<Integer> getDecryptedOutput() {
		return decryptedOutput;
	}

	public long combineToLong(int x, int y) {

		long c = (long) x << 32 | y & 0xFFFFFFFFL;

		return c;
	}

	public int splitFromLong(long l, boolean leftSide) {

		int aBack = (int) (l >> 32);
		int bBack = (int) l;

		String lStr = (String.format("%64s", Long.toBinaryString(l))).replace(' ', '0');

		if (leftSide) {
			return aBack;
			// return Integer.parseInt(lStr.substring(0, 31), 2);
		} else {
			return bBack;
			// return Integer.parseInt(lStr.substring(32, 63), 2);
		}

	}

	public ArrayList<Long> getDecryptedLong() {
		return decryptedLong;
	}

	public void setDecryptedLong(ArrayList<Long> decryptedLong) {
		this.decryptedLong = decryptedLong;
	}

	public ArrayList<Long> getEncryptedLong() {
		return encryptedLong;
	}

	public void setEncryptedLong(ArrayList<Long> encryptedLong) {
		this.encryptedLong = encryptedLong;
	}

	public ArrayList<Long> getInputLong() {
		return inputLong;
	}

	public void setInputLong(ArrayList<Long> inputLong) {
		this.inputLong = inputLong;
	}

	public char[] rotate(char[] chars, int shifts) {

		char[] result = new char[chars.length];
		if (shifts < 0) {
			shifts += chars.length;
		}

		for (int i = 0; i < chars.length; i++) {

			int oI = shifts + i;
			if (oI >= chars.length) {
				oI -= chars.length;
			}

			result[i] = chars[oI];

		}

		return result;

	}

	public char[] XOR(char[] a, char[] b) {

		char[] c = new char[a.length];

		for (int i = 0; i < a.length; i++) {

			if ((a[i] == '1' && b[i] == '1') || (a[i] == '0' && b[i] == '0')) {
				c[i] = '0';
			} else {
				c[i] = '1';
			}
		}

		return c;
	}

	public ArrayList<char[]> getEncryptedCharArr() {
		return encryptedCharArr;
	}

	public void setEncryptedCharArr(ArrayList<char[]> encryptedCharArr) {
		this.encryptedCharArr = encryptedCharArr;
	}

	public char[] splitFromcharArr(char[] a, boolean isLeftSide) {
		char[] c = new char[32];

		int i;
		if (isLeftSide) {
			i = 0;
		} else {
			i = 32;
		}

		for (int j = 0; j < 32; j++) {
			c[j] = a[i + j];
		}

		return c;
	}

	public ArrayList<char[]> getDecryptedCharArr() {
		return decryptedCharArr;
	}

	public void setDecryptedCharArr(ArrayList<char[]> decryptedCharArr) {
		this.decryptedCharArr = decryptedCharArr;
	}

	public char[] combineEqualArrays(char[] left, char[] right) {
		char[] result = new char[left.length];

		for (int i = 0; i < 32; i++) {
			result[i] = left[i];
		}

		for (int i = 32; i < 64; i++) {
			result[i] = right[i];
		}

		return result;
	}

	public ArrayList<int[]> getPointList() {
		return pointList;
	}

	public void setPointList(ArrayList<int[]> pointList) {
		this.pointList = pointList;
	}

	public int[] charArrtoIntArr(char[] c) {
		int[] result = new int[c.length];

		for (int i = 0; i < c.length; i++) {
			result[i] = c[i] - 48;
		}

		return result;
	}

	public int[] encode(int[] profile, int[] binary) {
		int[] result = new int[binary.length];

		for (int i = 0; i < binary.length; i++) {
			if (binary[i] == 0) {
				result[i] = -1 * profile[i];
			} else
				result[i] = profile[i];
		}

		return result;
	}

	public ArrayList<int[]> getEncPointList() {
		return encPointList;
	}

	public void setEncPointList(ArrayList<int[]> encPointList) {
		this.encPointList = encPointList;
	}

	public ArrayList<int[]> getDecpointList() {
		return decpointList;
	}

	public void setDecpointList(ArrayList<int[]> decpointList) {
		this.decpointList = decpointList;
	}

	public void addPoints(ArrayList<int[]> target, ArrayList<char[]> source) {

		for (char[] c : source) {
			target.add(encode(profile, this.charArrtoIntArr(c)));
		}

	}

	public int[] getFullEncPointsArr() {
		int[] result = new int[this.getEncPointList().size() * 64];

		for (int i = 0; i < this.getEncPointList().size(); i++) {

			for (int j = 0; j < 64; j++) {
				result[(i * 64) + j] = this.getEncPointList().get(i)[j];
			}
		}

		return result;
	}

	public int[] getFullDecPointsArr() {
		int[] result = new int[this.getDecpointList().size() * 64];

		for (int i = 0; i < this.getDecpointList().size(); i++) {

			for (int j = 0; j < 64; j++) {
				result[(i * 64) + j] = this.getDecpointList().get(i)[j];
			}
		}

		return result;
	}
	
	

	public static void printIntArr(int[] c) {
		System.out.print("{");
		for (int i = 0; i < c.length; i++) {
			System.out.print(" " + c[i]);
		}
		System.out.print("}\n");

	}

	public ArrayList<int[]> getInpointList() {
		return inpointList;
	}

	public void setInpointList(ArrayList<int[]> inpointList) {
		this.inpointList = inpointList;
	}
}