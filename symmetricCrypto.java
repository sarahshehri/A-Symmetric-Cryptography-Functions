package project_secourti;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
public class SymmetricCryptoFunction {

	public symmetricCryptoFunction() {}
		
		// TODO Auto-generated constructor stub
	       
	    private static SecretKeySpec secretKey;
	    private static byte[] key;

	    public static void main(String[] args) throws Exception {
	       int choice;
	        String inputFilePathForEncrypting = "file.txt";
	        String inputFilePathForDecrypting = "file.txt.encrypted";
	        String inputFilePathForHashing = "file.txt";
	        
            String inputFolderForEncrypting = "folder";
	        String inputFolderForDecrypting = "folder.Encrypted";
	       

	        System.out.println(getMenu());
	        Scanner sc = new Scanner(System.in);
	        while(true) {
	            getMenu();
	            System.out.print("Enter your choice: ");
	            choice = sc.nextInt();
	            if( choice ==1 || choice == 2 || choice == 3) {
	                if(choice != 3){
	                    if(choice == 1){
	                    	getFunction(choice,inputFilePathForEncrypting,inputFolderForEncrypting);
	                    }
	                    else if(choice == 2) {
	                    	getFunction(choice,inputFilePathForHashing , null);
	                    }
	                    
	                    else{
	                    	getFunction(choice, inputFilePathForDecrypting, inputFolderForDecrypting);
	                    }
	                    System.out.println(getMenu());
	                }
	                else {
	                    break;
	                }
	            }
	            else {
	                System.out.println(choice + " is not a valid choice. Enter choice 1 or 2 or 3");
	            }
	        }
	    }


	    static String getMenu(){

	        return  "      A SYMMETRIC CRYPTO SYSTEM\n"
	                + "======================================= \n"
	                + "MAIN MENU \n"
	                + "------------------------------------- \n"
	                + "1. Encryption \n"
	                + "2. Hashing \n"
	                + "3. Exit \n"
	                +  "-----------------------------------------\n";
	    }
	    static void getEncryption(int choice,String inputFilePath,String inputFolderPath) throws Exception {
	    	 String fileName;
		        String algorithm;
		        String key;
		        String folderName;
		        Scanner sc = new Scanner(System.in);
		        
	    	System.out.println("1. Encrypt \n2. Decrypt \n3.Back to main menu");
        	int typeEncryption =sc.nextInt();
        	switch(typeEncryption) {
        	case 1:
        		System.out.print("(1) File (2) Folder \n"
                        + "Enter your choice: ");
        		 int typeChoice = sc.nextInt();

                 if(typeChoice == 1){
                     System.out.print("Name: ");
                     fileName = sc.next();
                     System.out.print("Algorithm (AES, DES): ");
                     algorithm = sc.next();
                     if(!algorithm.equals("AES") && !algorithm.equals("DES")){
                         System.out.println("Not a valid algorithm");
                         break;
                    }
                    System.out.print("Key: ");
                    key = sc.next();
                    encrptFile(key,fileName,inputFilePath,algorithm);
        	}
            
                 else if(typeChoice == 2){
                    System.out.print("Folder Name: ");
                    folderName = sc.next();
                    System.out.print("Algorithm (AES, DES): ");
                    algorithm = sc.next();
                    if(!algorithm.equals("AES") && !algorithm.equals("DES")){
                        System.out.println("Not a valid algorithm");
                        break;
                    }
                    System.out.print("Key: ");
                    key = sc.next();
                    encrptFolder(key,folderName,inputFolderPath,algorithm);
             
               
        	}
               else if(typeChoice != 1 || typeChoice !=2){
                    System.out.println("Please enter either 1 or 2");
                }
                break;
               
        	
        	case 2: 
        		System.out.print("(1) File (2) Folder \n"
                        + "Enter your choice: ");
        		      typeChoice = sc.nextInt();

                 if(typeChoice == 1){
                     System.out.print("Name: ");
                     fileName = sc.next();
                     System.out.print("Algorithm (AES, DES): ");
                     algorithm = sc.next();
                     if(!algorithm.equals("AES") && !algorithm.equals("DES")){
                         System.out.println("Not a valid algorithm");
                         break;
                    }
                    System.out.print("Key: ");
                    key = sc.next();
                    decryptFile(key,fileName,inputFilePath,algorithm);
        	}
            
                else if(typeChoice == 2){
                    System.out.print("Folder Name: ");
                    folderName = sc.next();
                    System.out.print("Algorithm (AES, DES): ");
                    algorithm = sc.next();
                    if(!algorithm.equals("AES") && !algorithm.equals("DES")){
                        System.out.println("Not a valid algorithm");
                        break;
                    }
                    System.out.print("Key: ");
                    key = sc.next();
                    decryptFolder(key,folderName,inputFolderPath,algorithm);
             
               
            }
               else if(typeChoice != 1 || typeChoice !=2){
                    System.out.println("Please enter either 1 or 2");
                }
                break;
               
        	
                case 3:
                	
        		   getMenu();
        		   break;
        	
                case 4:
                	if (typeEncryption!=1 || typeEncryption!=2 || typeEncryption!=3) {
        		 System.out.println("Please enter either 1 or 2 or 3");}
        	
        	}
        	
	    }

	    static void getFunction(int choice,String inputFilePath,String inputFolderPath) throws Exception {
	        String fileName;
	        String algorithm;
	        String key;
	        Scanner sc = new Scanner(System.in);
	        try{
	            switch (choice) {
	            case 1:
	            	getEncryption(choice,inputFilePath,inputFolderPath);
	            	break;
	            
	            case 2:
	                        System.out.print("File Name: ");
	                        fileName = sc.next();
	                        System.out.print("Choose the Algorithm (SHA256, SHA512): ");
	                        algorithm = sc.next();
	                        if(!algorithm.equals("SHA256") && !algorithm.equals("SHA512")){
	                            System.out.println("Not a valid algorithm");
	                            break;
	                        }
	                        System.out.print("Key: ");
	                        key = sc.next();
	                        hashing(key,fileName,inputFilePath,algorithm);
	                    
	                  
	                              
	             break;
	            }
	            
	        }catch (Exception e) {
	            throw e;
	        }
	    }



	     static void encrptFile(String key, String fileName, String inputFilePath,String algorithm) throws Exception {
	        File encryptedFile = new File(fileName + ".encrypted");
	        String fileContent = new String(Files.readAllBytes(Paths.get(inputFilePath)));
	         Cipher cipher = null;
	        try{
	            if(algorithm.equals("AES")){
	               cipher = Cipher.getInstance("AES");
	            }
	            if(algorithm.equals("DES")) {
	                cipher = Cipher.getInstance("DES");
	            }
	            byte[] plainTextByte = fileContent.getBytes();
	            cipher.init(Cipher.ENCRYPT_MODE,generateSecretKey(key,algorithm));
	            byte[] encryptedByte = cipher.doFinal(plainTextByte);
	            Base64.Encoder encoder = Base64.getEncoder();
	            String encryptedText = encoder.encodeToString(encryptedByte);
	            BufferedWriter writer = new BufferedWriter(new FileWriter(encryptedFile));
	            writer.write(encryptedText);
	            writer.close();
	            System.out.println("Done! File " + inputFilePath + " is encrypted using " + algorithm +  "\n"
	                          + "Output file is " + fileName + ".encrypted\n" );

	        } catch (Exception e) {
	            e.printStackTrace();
	            throw new Exception(e);
	        }
	     }

	    static void decryptFile(String key, String fileName, String inputFilePath, String algorithm) throws Exception {
	        File decryptedFile = new File(fileName + ".decrypted");
	        String fileContent = new String(Files.readAllBytes(Paths.get(inputFilePath)));
	        Cipher cipher = null;
	        try{
	            if(algorithm.equals("AES")){
	                cipher = Cipher.getInstance("AES");
	            }
	            if(algorithm.equals("DES")) {
	                cipher = Cipher.getInstance("DES");
	            }
	            Base64.Decoder decoder = Base64.getDecoder();
	            byte[] encryptedTextByte = decoder.decode(fileContent);
	            cipher.init(Cipher.DECRYPT_MODE, generateSecretKey(key,algorithm));
	            byte[] decryptedByte = cipher.doFinal(encryptedTextByte);
	            String decryptedText = new String(decryptedByte);
	            BufferedWriter writer = new BufferedWriter(new FileWriter(decryptedFile));
	            writer.write(decryptedText);
	            writer.close();
	            System.out.println("Done! File " + inputFilePath + " is decrypted using " +algorithm +"\n"
	                    + "Output file is " + fileName + ".decrypted" );

	        } catch (Exception e) {
	            e.printStackTrace();
	            throw new Exception(e);
	        }
	    }

	    static void encrptFolder(String key, String folderName, String inputFolderPath,String algorithm) throws Exception {
	        File encryptedFolder = new File(folderName+".encrypted");
	        File inputFolder = new File(inputFolderPath);
	        String fileContent = "";
	        String fileName = "";
	        Cipher cipher = null;

	        try{
	            if(inputFolder.isDirectory()) {
	                File[] files = inputFolder.listFiles();
	                for (int i = 0; i < files.length; i++) {
	                    if(!encryptedFolder.exists()){
	                        encryptedFolder.mkdir();
	                    }
	                    fileContent = new String(Files.readAllBytes(Paths.get(files[i].getAbsolutePath())));
	                    fileName = removeExtension(files[i].getName());
	                    if (algorithm.equals("AES")) {
	                        cipher = Cipher.getInstance("AES");
	                    }
	                    if (algorithm.equals("DES")) {
	                        cipher = Cipher.getInstance("DES");
	                    }
	                    byte[] plainTextByte = fileContent.getBytes();
	                    cipher.init(Cipher.ENCRYPT_MODE, generateSecretKey(key, algorithm));
	                    byte[] encryptedByte = cipher.doFinal(plainTextByte);
	                    Base64.Encoder encoder = Base64.getEncoder();
	                    String encryptedText = encoder.encodeToString(encryptedByte);
	                    BufferedWriter writer = new BufferedWriter(new FileWriter(encryptedFolder + fileName + ".encrypted"));
	                    writer.write(encryptedText);
	                    writer.close();
	                }
	                System.out.println("Done! Folder " + inputFolderPath + "is encrypted using " + algorithm + "\n"
	                        + "Output folder is " + folderName+ "\n");
	            }

	        } catch (Exception e) {
	            e.printStackTrace();
	            throw new Exception(e);
	        }
	    }

	    static void decryptFolder(String key, String folderName, String inputFolderPath, String algorithm) throws Exception {
	        File decryptedFolder = new File(folderName+ ".decrypted");
	        File inputFolder = new File(inputFolderPath);
	        String fileContent = "";
	        String fileName = "";
	        Cipher cipher = null;

	        try{
	            if(inputFolder.isDirectory()) {
	                File[] files = inputFolder.listFiles();
	                for (int i = 0; i < files.length; i++) {
	                    if (!decryptedFolder.exists()) {
	                        decryptedFolder.mkdir();
	                    }
	                    fileContent = new String(Files.readAllBytes(Paths.get(files[i].getAbsolutePath())));
	                    fileName = removeExtension(files[i].getName());
	                    if (algorithm.equals("AES")) {
	                        cipher = Cipher.getInstance("AES");
	                    }
	                    if (algorithm.equals("DES")) {
	                        cipher = Cipher.getInstance("DES");
	                    }
	                    Base64.Decoder decoder = Base64.getDecoder();
	                    byte[] encryptedTextByte = decoder.decode(fileContent);
	                    cipher.init(Cipher.DECRYPT_MODE, generateSecretKey(key, algorithm));
	                    byte[] decryptedByte = cipher.doFinal(encryptedTextByte);
	                    String decryptedText = new String(decryptedByte);
	                    BufferedWriter writer = new BufferedWriter(new FileWriter(decryptedFolder + fileName + ".decrypted"));
	                    writer.write(decryptedText);
	                    writer.close();
	                }
	                System.out.println("Done! folder " + inputFolderPath + " is decrypted using " + algorithm + "\n"
	                        + "Output folder is " + folderName + "\n");

	            }

	        } catch (Exception e) {
	            e.printStackTrace();
	            throw new Exception(e);
	        }
	    }

	    static SecretKeySpec generateSecretKey(String userKey,String algorithm){
	        MessageDigest sha = null;
	        try {
	            key = userKey.getBytes("UTF-8");
	            sha = MessageDigest.getInstance("SHA-1"); 
	            key = sha.digest(key);                 
	            if(algorithm.equals("AES")){
	                key = Arrays.copyOf(key, 24);
	                secretKey = new SecretKeySpec(key, "AES");
	            }
	            if(algorithm.equals("DES")){
	                key = Arrays.copyOf(key, 8);
	                secretKey = new SecretKeySpec(key, "DES");
	            }
	        }
	        catch (NoSuchAlgorithmException e) {
	            e.printStackTrace();
	        }
	        catch (UnsupportedEncodingException e) {
	            e.printStackTrace();
	        }
	        return secretKey;
	    }

	    public static String removeExtension(String fileName) {
	        if (fileName.indexOf(".") > 0) {
	            return fileName.substring(0, fileName.lastIndexOf("."));
	        } else {
	            return fileName;
	        }

	    }
	    
	    static void hashing(String key, String fileName, String inputFilePath,String algorithm) throws Exception {
	    	 
	    	File hasingFile = new File(fileName +".Hash");
	       String fileContent = new String(Files.readAllBytes(Paths.get(inputFilePath)));
	       MessageDigest digest = null;
	        try {
	       	            if(algorithm.equals("SHA256")){
	               digest = MessageDigest.getInstance("SHA-256");
	            }
	            if(algorithm.equals("SHA512")) {
	                digest = MessageDigest.getInstance("SHA-512");
	            }
	            
	            byte[] plainTextByte = fileContent.getBytes();
	           byte[] hashedByetArray = digest.digest(plainTextByte);
	          String encoded = Base64.getEncoder().encodeToString(hashedByetArray);
	            BufferedWriter writer = new BufferedWriter(new FileWriter(hasingFile));
	            writer.write(encoded);
	            writer.close();
	            System.out.println("Done! File " +inputFilePath + " is hashed using " + algorithm +  "\n"
	                          + "Output file is " + fileName + ".hash\n" );

	        } catch (Exception e) {
	          e.printStackTrace();
	            throw new Exception(e);
	        }
	}
}





