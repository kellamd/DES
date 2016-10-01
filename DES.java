/* Author: Dan Kellam
 * Description: Implementation of Data Encryption Standard (DES) algorithm.
 * Limitations: Can only encrypt 1 message that is 64 bits (16 characters in hex) or less. Message 
 * 				and key can only be in hex.
 * Resource: http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
 * 		I used this site as a guide when implementing this project.
 */

import java.util.*;
import java.math.BigInteger;
public class DES {

	private int[] plainText, Key, CipherText, L, R, Kplus, C, D, MIP;
	private int[][] Cs, Ds, TempKs, Ks, Ls, Rs;
	private String Cipher, Plain;
	
	/*
	 * Tables for DES
	 */
	int[] IP = {58,    50,   42,    34,    26,   18,    10,    2,
			  	60,    52,   44,    36,    28,   20,    12,    4,
			  	62,    54,   46,    38,    30,   22,    14,    6,
			  	64,    56,   48,    40,    32,   24,    16,    8,
			  	57,    49,   41,    33,    25,   17,     9,    1,
			  	59,    51,   43,    35,    27,   19,    11,    3,
			  	61,    53,   45,    37,    29,   21,    13,    5,
			  	63,    55,   47,    39,    31,   23,    15,    7};
	

	int[] FinalIP = {40,     8,   48,    16,    56,   24,    64,   32,
            		 39,     7,   47,    15,    55,   23,    63,   31,
            		 38,     6,   46,    14,    54,   22,    62,   30,
            		 37,     5,   45,    13,    53,   21,    61,   29,
            		 36,     4,   44,    12,    52,   20,    60,   28,
            		 35,     3,   43,    11,    51,   19,    59,   27,
            		 34,     2,   42,    10,    50,   18,    58,   26,
            		 33,     1,   41,     9,    49,   17,    57,   25};
	
	int[] EBitSelect = {32,    1,     2,     3,     4,    5,
            		     4,    5,     6,     7,     8,    9,
            		     8,    9,    10,    11,    12,   13,
            		    12,    13,   14,    15,    16,   17,
            		    16,    17,   18,    19,    20,   21,
            		    20,    21,   22,    23,    24,   25,
            		    24,    25,   26,    27,    28,   29,
            		    28,    29,   30,    31,    32,    1};

	int[][] S1 = {{14,  4,  13,  1,   2, 15,  11,  8,   3, 10,   6, 12,   5,  9,   0,  7},
		      	  { 0, 15,   7,  4,  14,  2,  13,  1,  10,  6,  12, 11,   9,  5,   3,  8},
		      	  { 4,  1,  14,  8,  13,  6,   2, 11,  15, 12,   9,  7,   3, 10,   5,  0},
		      	  {15, 12,   8,  2,   4,  9,   1,  7,   5, 11,   3, 14,  10,  0,   6, 13}};
	
	int[][] S2 = {{15,  1,   8, 14,   6, 11,   3,  4,   9,  7,   2, 13,  12,  0,   5, 10},
		         { 3, 13,   4,  7,  15,  2,   8, 14,  12,  0,   1, 10,   6,  9,  11,  5},
		         { 0, 14,   7, 11,  10,  4,  13,  1,   5,  8,  12,  6,   9,  3,   2, 15},
		         {13,  8,  10,  1,   3, 15,   4,  2,  11,  6,   7, 12,   0,  5,  14,  9}};
	
	int[][] S3 = {{10,  0,   9, 14,   6,  3,  15,  5,   1, 13,  12,  7,  11,  4,   2,  8},
		     	  {13,  7,   0,  9,   3,  4,   6, 10,   2,  8,   5, 14,  12, 11,  15,  1},
		     	  {13,  6,   4,  9,   8, 15,   3,  0,  11,  1,   2, 12,   5, 10,  14,  7},
		     	  { 1, 10,  13,  0,   6,  9,   8,  7,   4, 15,  14,  3,  11,  5,   2, 12}};
	
	int[][] S4 = {{ 7, 13,  14,  3,   0,  6,   9, 10,   1,  2,   8,  5,  11, 12,   4, 15},
			  	  {13,  8,  11,  5,   6, 15,   0,  3,   4,  7,   2, 12,   1, 10,  14,  9},
			  	  {10,  6,   9,  0,  12, 11,   7, 13,  15,  1,   3, 14,   5,  2,   8,  4},
			  	  { 3, 15,   0,  6,  10,  1,  13,  8,   9,  4,   5, 11,  12,  7,   2, 14}};
	
	int[][] S5 = {{2, 12,   4,  1,   7, 10,  11,  6,   8,  5,   3, 15,  13,  0,  14,  9},
				  {14, 11,   2, 12,   4,  7,  13,  1,   5,  0,  15, 10,   3,  9,   8,  6},
				  { 4,  2,   1, 11,  10, 13,   7,  8,  15,  9,  12,  5,   6,  3,   0, 14},
				  {11,  8,  12,  7,   1, 14,   2, 13,   6, 15,   0,  9,  10,  4,   5,  3}};
	
	int[][] S6 = {{12,  1,  10, 15,   9,  2,   6,  8,   0, 13,   3,  4,  14,  7,   5, 11},
				  {10, 15,   4,  2,   7, 12,   9,  5,   6,  1,  13, 14,   0, 11,   3,  8},
				  { 9, 14,  15,  5,   2,  8,  12,  3,   7,  0,   4, 10,   1, 13,  11,  6},
				  { 4,  3,   2, 12,   9,  5,  15, 10,  11, 14,   1,  7,   6,  0,   8, 13}};
	
	int[][] S7 = {{ 4, 11,   2, 14,  15,  0,   8, 13,   3, 12,   9,  7,   5, 10,   6,  1},
				  {13,  0,  11,  7,   4,  9,   1, 10,  14,  3,   5, 12,   2, 15,   8,  6},
				  { 1,  4,  11, 13,  12,  3,   7, 14,  10, 15,   6,  8,   0,  5,   9,  2},
				  { 6, 11,  13,  8,   1,  4,  10,  7,   9,  5,   0, 15,  14,  2,   3, 12}};
	
	int[][] S8 = {{13,  2,   8,  4,   6, 15,  11,  1,  10,  9,   3, 14,   5,  0,  12,  7},
				  { 1, 15,  13,  8,  10,  3,   7,  4,  12,  5,   6, 11,   0, 14,   9,  2},
				  { 7, 11,   4,  1,   9, 12,  14,  2,   0,  6,  10, 13,  15,  3,   5,  8},
				  { 2,  1,  14,  7,   4, 10,   8, 13,  15, 12,   9,  0,   3,  5,   6, 11}};
	
	int[][][] SBoxes = {S1, S2, S3, S4, S5, S6, S7, S8};
	
	int[] P = {16,   7,  20,  21,
               29,  12,  28,  17,
                1,  15,  23,  26,
                5,  18,  31,  10,
                2,   8,  24,  14,
               32,  27,   3,   9,
               19,  13,  30,   6,
               22,  11,   4,  25};
			
	
	int[] PC1 = {57,49,41,33,25,17,9,
				  1,58,50,42,34,26,18,
				 10, 2,59,51,43,35,27,
				 19,11, 3,60,52,44,36,
				 63,55,47,39,31,23,15,
				  7,62,54,46,38,30,22,
				 14, 6,61,53,45,37,29,
				 21,13, 5,28,20,12, 4};
	
	int[] PC2 = {14,17,11,24, 1, 5,
				  3,28,15, 6,21,10,
				 23,19,12, 4,26, 8,
				 16, 7,27,20,13, 2,
				 41,52,31,37,47,55,
				 30,40,51,45,33,48,
				 44,49,39,56,34,53,
				 46,42,50,36,29,32};
	
	int[] LeftShifts = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
	
	
	public static void main(String args[])
	{
		/*
		 * Ask user for 64 bit message and key in hex and store in msg and k.
		 */
		Scanner in = new Scanner(System.in);
		System.out.println("Enter a 64 bit hex message you want to encrypt using DES.");
		String msg = in.nextLine();
		System.out.println("Enter the 64 bit key in hex.");
		String k = in.nextLine();
		in.close();
		
		/*
		 * Change hex string to equivalent binary string
		 */
		String ms = String.format("%64s", new BigInteger(msg, 16).toString(2)).replace(" ", "0");
		String ke = String.format("%64s", new BigInteger(k, 16).toString(2)).replace(" ", "0");
		
		/*
		 * Create a DES object(d) with the message(ms) and key(ke) given.
		 * This automatically encrypts the message and stores the cipher text.
		 */
		DES d = new DES(ms, ke);
		
		System.out.println("Cipher Text = " + d.getCipher());
		System.out.println("Decrytped Cypher Text = " + d.Decrypt());
		

		/*
		String msg2 = "0000000100100011010001010110011110001001101010111100110111101110"; // 0123456789abcdee hex in binary
		 
		DES f = new DES(msg2, ke);

		System.out.println("Cipher Text = " + f.getCipher());
		System.out.println("Decrytped Cypher Text = " + f.Decrypt());
		*/
	
	}
	
	
	/* Encrypts the message using DES
	*  Arguments: 
	* 		String msg - Binary string of length 64. The message you want to encrypt
	* 		String K - Binary string of length 64. The key used to encrypt.
	*  Returns: 
	*  		String Cipher - Cipher text in hex.
	*/
	public String Encrypt(String msg, String K)
	{
		Cipher = ""; 				// Holds cipher text after encryption
		Cs = new int[16][28];  		// Left half of subkeys after shifting
		Ds = new int[16][28];  		// Right half of subkeys after shifting
		TempKs = new int[16][56]; 	// Combined C's and D's before PC-2
		Ks = new int[16][48];		// Competed subkeys from PC-2
		Ls = new int[16][32]; 		// Holds left half of each round of SBoxes
		Rs = new int[16][32]; 		// Hold right half of each round of SBoxes
		
		/*
		 * converts the binary strings to int[] 
		 */
		plainText = BinaryStringToIntArray(msg);
		Key = BinaryStringToIntArray(K);
		
		
/******************************************************************************
 * 																			  *
 * 				                SUBKEY CREATION								  *
 * 																			  *	
 * 																			  *
 ******************************************************************************/
		/*
		 *  The 64-bit Key is permuted according to PC-1.
		 *  Note only 56 bits of the original Key appear in Kplus
		 */
		Kplus = ApplyPC1(Key);
		
		/*
		 * Split 56 bit Kplus into left and right halves, C and D, where each half has 28 bits.
		 */
		CreateCandD();
		
		
		/*
		 * With C and D defined, create sixteen blocks Cn and Dn, 1<=n<=16.
		 * Each pair of blocks Cn and Dn is formed from the previous pair Cn-1 and Dn-1, 
		 * respectively, for n = 1, 2, ..., 16, using the LeftShifts array which is the 
		 * number of shifts each round should do.
		 * 	
		 */	
		int[] currC = new int[28];
		int[] currD = new int[28];
		currC = C;
		currD = D;
		for(int i = 0; i < 16; i ++)
		{
			int[] hold = new int[16];
			hold = LeftShift(currC, LeftShifts[i]);
			Cs[i] = hold;
			currC = hold;
			hold = LeftShift(currD, LeftShifts[i]);
			Ds[i] = hold;
			currD = hold;
		}

		
		/*
		 * TempKs holds concatenated C's and D's
		 */
		for(int i = 0; i < 16; i++)
		{
			TempKs[i] = Combine(Cs[i], Ds[i]);
		}
		
		
		/*
		 * Applies all CD concatenations held in TempKs to PC-2.
		 * Each CD pair has 56 bits, but PC-2 only uses 48 of these.
		 * Ks holds the completed subkeys. Each one is 48 bits.	
		 */
		for(int i = 0; i < 16; i++)
		{
			Ks[i] = ApplyPC2(TempKs[i]);
		}

		
		
/******************************************************************************
* 																			  *
* 				      Encode 64-bit block of data							  *
* 																			  *	
* 																			  *
******************************************************************************/		
		/*
		 * Applies the 64 bit message to IP to get a new permuted message, MIP. Still 64 bits
		 */
		MIP = ApplyIP(plainText);
		
		/*
		 * Divide the permuted block MIP into a left half L of 32 bits, and a right half R of 32 bits.		
		 */
		CreateLandR();
		
		/*
		 * We now proceed through 16 iterations, for 1<=n<=16, using a function f which operates on two 
		 * blocks--a data block of 32 bits and a key Kn of 48 bits--to produce a block of 32 bits. 
		 * Let + denote XOR addition, (bit-by-bit addition modulo 2). Then for n going from 1 to 16 
		 * we calculate:
		 *
		 *	Ln = Rn-1 
		 *	Rn = Ln-1 + f(Rn-1,Kn)
		 *
		 * This results in a final block, for n = 16, of L16R16. That is, in each iteration, 
		 * we take the right 32 bits of the previous result and make them the left 32 bits of the 
		 * current step. For the right 32 bits in the current step, we XOR the left 32 bits of the 
		 * previous step with the calculation f .				
		 */
		int[] currR = R;
		int[] currL = L;
		for(int i = 0; i < 16; i++)
		{
			Ls[i] = currR;
			Rs[i] = FindR(currL, f(currR, Ks[i]));
			currR = Rs[i];
			currL = Ls[i];
		}

		
		/*
		 * At the end of the sixteenth round we have the blocks L16 and R16. We then reverse 
		 * the order of the two blocks into the 64-bit block.
		 * R16L16
		 */
		int[] rl = Combine(Rs[15], Ls[15]);
		
		/*
		 *  Applies the 64 bit block to the final IP to get the cipher text in binary
		 */
		CipherText = ApplyFinalIP(rl);
		
		/*
		 * Changes int[] to BinaryString
		 */
		String cipher = IntArrayToBinaryString(CipherText);
		
		/*
		 * Changes the binary string to a hex string with leading zeroes
		 */
		String HexCipher = String.format("%16s", new BigInteger(cipher, 2).toString(16)).replace(" ", "0");
		

		Cipher = HexCipher;
		return Cipher;
	}
	
	
	/* Dencrypts the message
	* Returns: String pText - plain text in hex.
	* Decryption is the same as encryption except the creation order of L's and R's are 
	* reversed and Keys are used in reverse order.
	*/
	public String Decrypt()
	{

		String pText = "";  	// Holds plain text after decryption
		String cText = Cipher;	// Create a copy of the cipher text in hex;
		
		/*
		 * Changes the hex string cText to a binary string decIP. Then changes decIP to an int[].
		 */
		String decIP = String.format("%64s", new BigInteger(cText, 16).toString(2)).replace(" ", "0");
		int[] dIP = BinaryStringToIntArray(decIP);
		
		/*
		 * Applies dIP, which is the cipher text in binary, to the IP table. Same process as Encrypt.
		 */
		MIP = ApplyIP(dIP);
		
		/*
		* Divide the permuted block MIP into a left half L of 32 bits, and a right half R of 32 bits.	
		* Same process as Encrypt.	
		*/
		CreateLandR();
		
		

		/*
		* We now proceed through 16 iterations, for 1<=n<=16, n going from 16 to 1 
		* we calculate:
		*
		*	Rn = Ln+1 
		* 	Ln = Rn+1 + f(Ln+1,Kn)
		*
		* This results in a final block, for n = 0, of L0R0.
		* This is the reverse order of encrypt. 	
		*/		
		int[] currR = L;
		int[] currL = R;
		for(int i = 15; i >= 0; i--)
		{
			Rs[i] = currL;
			Ls[i] = FindR(currR, f(currL, Ks[i]));
			currR = Rs[i];
			currL = Ls[i];
		}
		

		/*
		* At the end of the sixteenth round we have the blocks L0 and R0. We then reverse 
		* the order of the two blocks into the 64-bit block.
		* L0R0
		* Same process as encrypt.
		*/	
		int[] lr = Combine(Ls[0], Rs[0]);

		
		/*
		*  Applies the 64 bit block to the final IP to get the plain text in binary
		*/		
		plainText = ApplyFinalIP(lr);
		
		
		/*
		 * Changes the plain text int[] to binary string.
		 */
		String plain = IntArrayToBinaryString(plainText);

		
		/*
		 * Changes the binary string to a hex string with leading zeroes
		 */
		String PlainCipher = String.format("%16s", new BigInteger(plain, 2).toString(16)).replace(" ", "0");


		Plain = PlainCipher;
		pText = Plain;
		return pText;
		
	}
	
	
	/*
	 * DES constructor.
	 * Arguments:
	 * 		String msg - 64 bit plain text message in a binary string
	 * 		String K - 64 bit key in a binary string
	 */
	public DES(String msg, String K)
	{
		Encrypt(msg,K);
	}
	
	/*
	 * Returns the cipher text of the encrypted message
	 */
	public String getCipher()
	{
		return Cipher;
	}
	
	
	/*
	 * Changes a binary string to an int[]
	 * Argument:
	 * 		String s - binary string to be converted to int[]
	 * Returns:
	 * 		int[] a - int[] that mimics a binary string.	
	 */
	private int[] BinaryStringToIntArray(String s)
	{
		int[] a = new int[s.length()];
		for(int i = 0; i < s.length();i++)
		{
			a[i] = Character.getNumericValue(s.charAt(i));
		}
		return a;
	}

	/*
	* Changes an int[] to a binary string
	* Argument:
	* 		int[] arr - int[] that mimics a binary string.
	* Returns:
	* 		BString s - binary string equivalent to the int[].	
	*/	
	private String IntArrayToBinaryString(int[] arr)
	{
		String BString = "";
		for(int i = 0; i < arr.length; i++)
		{
			BString += Integer.toString(arr[i]);
		}
		return BString;
	}
	
	
	/*
	 * Applies the given int[] of 64 bits to PC-1 and returns int[] of 56 bits.	
	 */
	private int[] ApplyPC1(int[] key)
	{
		int[] PC1_Key = new int[56];
		for(int i = 0; i < PC1.length; i++)
		{
			PC1_Key[i] = key[PC1[i]-1];
		}
		return PC1_Key;
	}

	/*
	 * Split 56 bit Kplus into left and right halves, C and D, where each half has 28 bits.
	 */
	private void CreateCandD()
	{
		D = new int[28];
		C = new int[28];
		for(int i = 0; i < 56;i++)
		{
			if(i < 28)
			{
				C[i%28] = Kplus[i];
				
			}
			else
			{
				D[i%28] = Kplus[i];
			}
		}
	}
	
	/*
	 *  Circular left shift of the int[] bit, shift number of times.
	 *  Arguments:
	 *  	int[] bits - The int[] to left shift.
	 *  	int shifts - number of left shifts. 1 <= Shift <= 2. 
	 *  Returns:
	 *  	int[] temp - left shifted int[].
	 */
	private int[] LeftShift(int[] bits, int shift)
	{
		/*
		 * Always does one left shift.
		 */
		int[] temp = new int[bits.length];
		int replace = bits[0];
		System.arraycopy(bits, 1, temp, 0, bits.length-1);
		temp[temp.length - 1] = replace;
		replace = temp[0];
		
		/*
		 * Do another left shift if needed
		 */
		if(shift == 2)
		{
			int[] temp2 = new int[bits.length];
			System.arraycopy(temp, 1, temp2, 0, bits.length-1);
			temp2[temp2.length - 1] = replace;
			return temp2;
		}
		return temp;
	}
	

	/*
	 * Concatenates the two int[].
	 * Arguments:
	 * 		int[] left - left int[].
	 * 		intp[ right - right int[]
	 * Returns:
	 * 		int[] fullArr - full concatenated int[].	
	 */
	private int[] Combine(int[] left, int[] right)
	{
		int[] fullArr = new int[left.length + right.length];
		System.arraycopy(left, 0, fullArr, 0, left.length);
		System.arraycopy(right, 0, fullArr, left.length, right.length);
		return fullArr;
	}

	/*
	* Applies the given int[] of 56 bits to PC-2 and returns int[] of 48 bits.		
	*/
	private int[] ApplyPC2(int[] k)
	{
		int[] PC2_Key = new int[48];
		
		for(int i = 0; i < PC2.length; i++)
		{
			PC2_Key[i] = k[PC2[i]-1];
		}
		
		return PC2_Key;
	}

	/*
	* Applies the given int[] of 64 bits to PC-2 and returns int[] of 64 bits.		
	*/
	private int[] ApplyIP(int[] m)
	{
		int[] msg = new int[64];
		
		for(int i = 0; i < IP.length; i++)
		{
			msg[i] = m[IP[i]-1];
		}
		
		return msg;
	}
	
	
	/*
	 * Split 64 bit MIP into left and right halves, L and R, where each half has 32 bits.
	 */
	private void CreateLandR()
	{
		L = new int[32];
		R = new int[32];
		for(int i = 0; i < 64;i++)
		{
			if(i < 32)
			{
				L[i%32] = MIP[i];	
			}
			else
			{
				R[i%32] = MIP[i];				
			}
		}
	}
	
	
	/*
	 * Applies the given int[] of 32 bits to PC-1 and returns int[] of 48 bits.	
	 */
	private int[] ApplyEBitSelect(int[] r)
	{
		int[] NewR = new int[48];
		
		for(int i = 0; i < EBitSelect.length; i++)
		{
			NewR[i] = r[EBitSelect[i]-1];
		}
		
		return NewR;
	}
	
	
	/*
	 * Logical XOR between two int[]	
	 */
	private int[] XOR(int[] L, int[] R)
	{
		int[] xorArr = new int[L.length];
		for(int i = 0; i < L.length; i++)
		{
			xorArr[i] = L[i]^R[i];
		}
		return xorArr;
	}
	
	
	/*
	 * Splits the int[] of length 48 into 8 blocks of length 6
	 */
	private int[][] SplitIntoBlocks(int[] xor)
	{
		int blockNum = 0;
		int[][] blocks = new int[8][6];
		for(int i = 0; i < xor.length; i++)
		{
			if(i > 0 && i % 6 == 0)
				blockNum++;
			
			blocks[blockNum][i%6] = xor[i];
			
		}
		return blocks;
	}
	
	
	/*
	 * Applies the given int[] block of length 6 to the given S Box from the SBoxNum.
	 * Returns int[] of length 4 after applying SBox.
	 */
	private int[] ApplySBox(int SBoxNum, int[] block)
	{
		String blockString = IntArrayToBinaryString(block);
		String y = "";
		String x = "";
		for(int i = 0; i < blockString.length(); i++)
		{
			if(i == 0 || i == 5)
				y += Character.toString(blockString.charAt(i));
			else
				x += Character.toString(blockString.charAt(i));
		}
		int Y = Integer.parseInt(y,2);	
		int X = Integer.parseInt(x,2);
		
		int BoxValue = SBoxes[SBoxNum][Y][X];
		
		String BoxValString = String.format("%4s", Integer.toBinaryString(BoxValue)).replace(' ', '0');
		return BinaryStringToIntArray(BoxValString);
	}
	
	
	/*
	 * Combines the given list of blocks into a single int[] of length 32.	
	 */
	private int[] CombineBlocks(int[][] b)
	{
		int[] CombinedBlocks = new int[32];
		int count = 0;
		for(int i = 0; i < 8; i++)
		{
			for(int j = 0; j < 4; j++)
			{
				CombinedBlocks[count] = b[i][j];
				count++;
			}
		}
		return CombinedBlocks;
	}
	
	
	/*
	 * Applies the given int[] of length 32 to P and returns int[] of length 32.	
	 */
	private int[] ApplyP(int[] arr)
	{
		int[] p = new int[32];
		for(int i = 0; i < P.length; i++)
		{
			p[i] = arr[P[i]-1];
		}
		return p;
	}
	
	
	/*
	 * Feistel function
	 * Arguments:
	 * 		int[] R - int[] of length 32 which is right half of the current round of applying S Boxes.
	 * 		int[] ke - int[] of length that is the current subkey in use in the current round of applying S Boxes
	 * Returns:
	 * 		int[] f - int[] of length 32 of the completed Feistal function.
	 */
	private int[] f(int[] R, int[] ke)
	{
		int[] newR = ApplyEBitSelect(R);
		
		int[] xor = XOR(ke, newR);
		
		int[][] blocks = SplitIntoBlocks(xor);
		int[][] BlocksAfterSBoxes = new int[8][4];
		
		for(int i = 0; i < 8; i++)
		{
			int[] SB = ApplySBox(i,blocks[i]);
			BlocksAfterSBoxes[i] = SB;
		}
		
		int[] CombinedBl = CombineBlocks(BlocksAfterSBoxes);
		
		int[] f = ApplyP(CombinedBl);
		
		return f;
	}
	
	
	/*
	 * XOR the current left in the SBox round with the completed f function to find completed R half.
	 */
	int[] FindR(int[] L, int[] F)
	{
		return XOR(L,F);
	}
	
	
	/*
	 * Applies the given int[] of length 64 to Final IP and returns int[] of length 64 which is the final
	 * Cipher text in binary.	
	 */
	private int[] ApplyFinalIP(int[] arr)
	{
		int[] p = new int[64];
		for(int i = 0; i < FinalIP.length; i++)
		{
			p[i] = arr[FinalIP[i]-1];
		}
		return p;
	}
	
}
