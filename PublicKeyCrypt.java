import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Random;
import java.util.Scanner;
import java.math.BigInteger;

public class PublicKeyCrypt {
	
	private final static int BLOCKSIZE = 32;
	
	// string split function, to fix bug with new lines
	private static String[] splitString (String s, int interval){
		int arrayLength = (int) Math.ceil(((s.length() / (double)interval)));
	    String[] result = new String[arrayLength];

	    int j = 0;
	    int lastIndex = result.length - 1;
	    for (int i = 0; i < lastIndex; i++) {
	        result[i] = s.substring(j, j + interval);
	        j += interval;
	    }
	    result[lastIndex] = s.substring(j);

	    return result;
	}
	
	// function from stackoverflow to convert string to binary
	private static String AsciiToBinary(String asciiString, int length){
		byte[] bytes = asciiString.getBytes();
		StringBuilder binary = new StringBuilder();
		for (byte b : bytes){
			int val = b;
			for (int i = 0; i < 8; i++){
				binary.append((val & 128) == 0 ? 0 : 1);
				val <<= 1;
			}
		}
		String bin = binary.toString();
		while(bin.length() < length*8){
			bin = "0"+bin;
		}
		return bin;
	}
	
	// Square and multiply for fast modulo exponentiation
	private static BigInteger SquareAndMultiply(BigInteger num, BigInteger exponent, BigInteger modulo){
		BigInteger value = new BigInteger("0");
		// if exponent is 1
		if(exponent == new BigInteger("1"))
			return exponent.mod(modulo);
		// if exponent is 0
		if(exponent == new BigInteger("0"))
			return new BigInteger("1");
		
		//convert exponent to binary string
		String exponentbin = exponent.toString(2);
		//iterate string
		for(int i = 0; i < exponentbin.length(); i++){
			if(i == 0){
				value = num;
				continue;
			}
			if(Character.getNumericValue(exponentbin.charAt(i)) == 1)
				value = (value.multiply(value).multiply(num)).mod(modulo);
			else
				value = (value.multiply(value)).mod(modulo);
		}
		return value;
	}
	
	// Miller Rabin primality test using built in function
	private static Boolean MillerRabin(BigInteger num){
		return num.isProbablePrime(20);
	}
	
	// Generate Random big integer between 0 and n
	private static BigInteger randomBigInteger(BigInteger n, Random random){
		int maxNumBitLength = n.bitLength();
		BigInteger RandomBigInt;
		do {
			RandomBigInt = new BigInteger(maxNumBitLength, random);
		} while (RandomBigInt.compareTo(n) >= 0);
		return RandomBigInt;
	}
	
	// Key Generation (option 1)
	private static void KeyGeneration(int rngseed) throws IOException{
		System.out.println("Generating keys...");
		//Seed random number generator
		Random random = new Random(rngseed);
		
		// generate p
		BigInteger q;
		BigInteger p;
		BigInteger g = new BigInteger("2"); // generator is 2
		do{
			do {
				q = new BigInteger(BLOCKSIZE, random);
			} while(!(MillerRabin(q)&& (q.mod(new BigInteger("12")).equals(new BigInteger("5")))));
			p = g.multiply(q).add(new BigInteger("1"));
			
		} while(!(MillerRabin(p) && p.bitLength() > BLOCKSIZE));
		// generate random d
		BigInteger d = randomBigInteger (p, random);
		// compute e2
		BigInteger e2 = SquareAndMultiply(g,d,p);
		// create public and private key files
		PrintWriter writer = new PrintWriter("pubkey.txt", "UTF-8");
		writer.print(p+" "+g+" "+e2);			
		writer.close();
		PrintWriter writer2 = new PrintWriter("prikey.txt", "UTF-8");
		writer2.print(p+" "+g+" "+d);			
		writer2.close();
		
		System.out.println("Public key = p:"+ p+" g(e1):"+g+" e2:"+e2);
		System.out.println("Private key = p:"+ p+" g(e1):"+g+" d:"+d);
		System.out.println("Key Generation Finished!");
	}
	
	// Encryption (option 2)
	private static void Encryption() throws IOException{
		System.out.println("Encrypting ptext.txt...");
		
		//Seed random number generator
			Random random = new Random();
				
		// get pubkey info
		String pubkeyfile[] = new Scanner(new File("pubkey.txt")).useDelimiter("\\Z").next().split("\\s+");
		BigInteger p = new BigInteger(pubkeyfile[0]);
		BigInteger g = new BigInteger(pubkeyfile[1]);
		BigInteger e2 = new BigInteger(pubkeyfile[2]);
		// get plaintext file input
		String plaintextfile[] = splitString(new Scanner(new File("ptext.txt")).useDelimiter("\\Z").next(),4);//.split("(?<=\\G.{4})");
		
		// encrypt 32-bit blocks
		PrintWriter writer = new PrintWriter("ctext.txt", "UTF-8");
		for(int i = 0; i < plaintextfile.length; i++){
			// calculate m
			String binaryblock = AsciiToBinary(plaintextfile[i],plaintextfile[i].length());
			while(binaryblock.length() < BLOCKSIZE)
				binaryblock = binaryblock.concat("0");
			int mvalue = Integer.parseInt(binaryblock, 2);
			BigInteger m = new BigInteger(Integer.toString(mvalue)); 
			
			// choose rand k from 0 to p-1
			BigInteger k = randomBigInteger(p, random);
			
			// calculate c1 and c2
			BigInteger c1 = SquareAndMultiply(g,k,p);
			BigInteger c2 = (SquareAndMultiply(e2,k,p).multiply(m.mod(p))).mod(p);
			
			// write to ctext.txt
			if(i != 0)
				writer.print(" ");
			writer.print(c1+" "+c2);
			
			System.out.println("m"+i+": ("+c1+","+c2+")");
		}
		writer.close();
		System.out.println("Encryption Finished!");
	}
	
	// Decryption (option 3)
	private static void Decryption()throws IOException{
		System.out.println("Decrypting ctext.txt...");
		// get private key info
		String prikeyfile[] = new Scanner(new File("prikey.txt")).useDelimiter("\\Z").next().split("\\s+");
		BigInteger p = new BigInteger(prikeyfile[0]);
		BigInteger g = new BigInteger(prikeyfile[1]);
		BigInteger d = new BigInteger(prikeyfile[2]);
		// get cipher text file input
		String ciphertextfile[] = new Scanner(new File("ctext.txt")).useDelimiter("\\Z").next().split("\\s+");
		
		// decrypt
		PrintWriter writer = new PrintWriter("dtext.txt", "UTF-8");
		for(int i = 0; i < ciphertextfile.length; i+=2){
			// get m
			BigInteger p1d = p.subtract(new BigInteger("1")).subtract(d);
			BigInteger c1 = new BigInteger(ciphertextfile[i]);
			BigInteger c2 = new BigInteger(ciphertextfile[i+1]);
			BigInteger mvalue = (SquareAndMultiply(c1,p1d,p).multiply(c2.mod(p))).mod(p);
			
			// get binary of BigInteger
			Long mlongvalue = mvalue.longValue();
			String mbinary = Long.toBinaryString(mlongvalue);
			while(mbinary.length() < BLOCKSIZE)
				mbinary = "0"+mbinary;
			
			// turn into ascii text
			String mbinarycharacters[] = mbinary.split("(?<=\\G.{8})");
			for(int j = 0; j < mbinarycharacters.length; j++){
				//bug fix for no character
				if(new String("00000000").equals(mbinarycharacters[j])){
					continue;
				}	
				String character = Character.toString((char)Integer.parseInt(mbinarycharacters[j],2));
				writer.print(character);
				System.out.print(character);
			}
		}
		writer.close();
		System.out.println("");
		System.out.println("Decryption Finished!");
	}
	
	public static void main(String[] args) throws IOException {
		Scanner scanner = new Scanner(System.in);
		// prompt user to choose between key generation, encryption, or decryption
		System.out.print("Type - 1 for for key generation, 2 for encryption, 3 for decryption: ");
		int userinput = scanner.nextInt();
		
		// key generation
		if(userinput == 1){
			// prompt user for number to seed rng
			System.out.print("Enter a number to seed random number generator: ");
			int rngseed = scanner.nextInt();
			KeyGeneration(rngseed);
		}
		// encryption
		else if(userinput == 2){
			Encryption();
		}
		// decryption
		else if(userinput == 3){
			Decryption();
		}
		// Otherwise invalid input
		else{
			System.out.println("Error: Invalid Option!");
		}
	}
}
