package AES_Mutlu_Zeynep;

/**
 * TOBB UNIVERSITY
 * Cyber Security Master Programme
 *
 * @ subject:
 * AES DIFFUSION ANALYZE PROGRAMME
 *
 * @ working topics:
 * What happens when we change one bit from plain text while we are working on AES Encryption?
 * What happens when we change one bit from key text while we are working on AES Encryption?
 *
 * @ class:     Mathematical Cryptography
 * @ coder:     Zeynep Delal Mutlu
 * @ lecturer:  Yesem Peker
 * @ location:  Ankara,Turkey
 * @ date:      6 Nov 2019
 *
 */

import java.io.*;
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.Scanner;


public class Main {

    //Static variables which are used by all class functions.
    private static int generalMenuOption;
    private static int textnumber;
    private static int bitnumber;
    private static int randomIndex;
    private static int numOfChangedBits;
    private static AES aes = new AES();

    //Main Function
    public static void main(String[] args) throws IOException {

        //Variables
        String keyTxt;
        String plainTxt;
        String bitStringOfPlainText;
        String changedStringInBits;
        String bitStringOfKeyText;
        String changedKeyStringInBits;
        String changedText = "";
        String changedKeyTxt;
        StringBuilder textFile = new StringBuilder();

        //Asking general menu for the first time
        GeneralMenu();

        //All works are done here
        do{
            //'AES_Triples.txt' is read
            URL url = Main.class.getResource("AES_Triples.txt");
            File file = new File(url.getPath());
            FileReader fr = new FileReader(file);
            BufferedReader buffer = new BufferedReader(fr);
            String line = buffer.readLine();

            //Option 1: Changed bits of all texts.
            //Output is 'data.txt' file
            if(generalMenuOption == 1){
                int count = 1;
                double overallPercentage = 0;

                //Getting all lines from the 'AES_Triples.txt' line by line
                while(line != null) {
                    //Parse key text and plaintext from the file line with respect to space
                    System.out.println("\n" + count + " : " + line);
                    String[] parts = line.split(" ");
                    keyTxt = parts[0];
                    plainTxt = parts[1];

                    //Convert hex plaintext into bits
                    bitStringOfPlainText = StringToBit(plainTxt);
                    //Change one bit from plaintext randomly
                    changedStringInBits = ChangeBitRandomly(bitStringOfPlainText);

                    //Convert changed text which is string format with bits to hex format
                    byte[] bconvert = new BigInteger(changedStringInBits, 2).toByteArray();
                    byte[] b = new byte[16];
                    if(bconvert.length == 17){
                        for(int i = 0; i < 16; i++)
                            b[i] = bconvert[i+1] ;
                    }
                    else{
                        b = bconvert;
                    }
                    changedText = Util.toHEX1(b);

                    //Encrypt Plain Text
                    //It is also equal to parts[2] (third string in 'AES_Triples.txt')
                    aes.setKey(Util.hex2byte(keyTxt)); //Set aes key
                    byte[] plainTextBytes =  Util.hex2byte(plainTxt);
                    byte[] plainTextEncrypted = aes.encrypt(plainTextBytes);

                    //Encrypt Changed Text
                    byte[] changedTextBytes =  Util.hex2byte(changedText);
                    byte[] changedTextEncrypted = aes.encrypt(changedTextBytes);

                    //Calculate the bit difference between cipher texts which use normal plaintext and one bit changed plaintext
                    double difference = PercentageOfDifference(Util.toHEX1(plainTextEncrypted), Util.toHEX1(changedTextEncrypted));

                    //Prepare string outputs for text file and also print outputs on terminal
                    overallPercentage += difference; //Sum all changed bit numbers to calculate percentage of changed bit number.
                    textFile.append(format2(plainTxt, randomIndex, numOfChangedBits, difference));
                    String eachOutput = format1(plainTxt, randomIndex, numOfChangedBits, changedText, Util.toHEX1(plainTextEncrypted), Util.toHEX1(changedTextEncrypted), difference);
                    System.out.println(eachOutput);
                    line = buffer.readLine();
                    count++;
                }

                //Header output for text file: headers and percentage of changed bit in all cipher texts.
                String header = "PLAIN TEXT BITS CHANGE\n\nPlaintext\t\t\t\tToggle Bit\tFlip Bits\tPercentage of Changed Bits\n";
                textFile.insert(0, header + "\nAverage percentage of 100 changed cipher text: " + (overallPercentage / 100) + "\n\n");

                // Create file and write textfile
                PrintWriter writer = new PrintWriter("data.txt", StandardCharsets.UTF_8);
                writer.println(textFile);
                writer.close();

                //Clear variables
                changedText = "";
                textFile = new StringBuilder();
                RefreshAllVariables();
            }

            //Option 11: Changed bits of all key texts.
            //Output is 'changedKey.txt' file
            //All steps are same as Option 1 above.
            //Only difference is: key text is used instead of plain text.
            else if(generalMenuOption == 11){
                int count = 1;
                double overallPercentage = 0;
                line = buffer.readLine();

                //Getting all lines from the 'AES_Triples.txt' line by line
                while(line != null) {
                    System.out.println("\n" + count + " : " + line);
                    String[] parts = line.split(" ");
                    keyTxt = parts[0];
                    plainTxt = parts[1];

                    //Convert hex key text into bits
                    bitStringOfKeyText = StringToBit(keyTxt);
                    //Change one bit from key text randomly
                    changedKeyStringInBits = ChangeBitRandomly(bitStringOfKeyText);

                    //Convert changed key text which is string format with bits to hex format
                    byte[] bconvert = new BigInteger(changedKeyStringInBits, 2).toByteArray();
                    byte[] b = new byte[16];
                    if(bconvert.length == 17){
                        for(int i = 0; i < 16; i++){
                            b[i] = bconvert[i+1] ;
                        }
                    }
                    else{
                        b = bconvert;
                    }
                    changedKeyTxt = Util.toHEX1(b);

                    //Encrypt Text with not-changed aes key
                    aes.setKey(Util.hex2byte(keyTxt)); //Set not changed aes key
                    byte[] plainTextBytes =  Util.hex2byte(plainTxt);
                    byte[] plainTextNormalKeyEncrypted = aes.encrypt(plainTextBytes);

                    //Encrypt Text with changed aes key
                    aes.setKey(Util.hex2byte(changedKeyTxt)); //Set changed aes key
                    byte[] changedKeyTextEncrypted = aes.encrypt(plainTextBytes);

                    //Calculate the bit difference between cipher texts which use normal key text and one bit changed key text
                    double difference = PercentageOfDifference(Util.toHEX1(plainTextNormalKeyEncrypted), Util.toHEX1(changedKeyTextEncrypted));

                    //Prepare string outputs for text file and also print outputs on terminal
                    overallPercentage += difference; //Sum all changed bit numbers to calculate percentage of changed bit number.
                    textFile.append(format2(plainTxt, randomIndex, numOfChangedBits, difference));
                    String eachOutput = format1(plainTxt, randomIndex, numOfChangedBits, changedText, Util.toHEX1(plainTextNormalKeyEncrypted), Util.toHEX1(changedKeyTextEncrypted), difference);
                    System.out.println(eachOutput);
                    line = buffer.readLine();
                    count++;
                }

                //Header output for text file: headers and percentage of changed bit in all cipher texts.
                String header = "KEY TEXT BITS CHANGE\n\nPlaintext\t\t\t\tToggle Bit\tFlip Bits\tPercentage of Changed Bits\n";
                textFile.insert(0, header + "\nAverage percentage of 100 changed cipher text: " + (overallPercentage / 100) + "\n\n");

                // Create file and write text file
                PrintWriter writer = new PrintWriter("changedKey.txt", StandardCharsets.UTF_8);
                writer.println(textFile);
                writer.close();

                //Clear variables
                changedText = "";
                textFile = new StringBuilder();
                RefreshAllVariables();
            }

            //Option 2: Changed one selected bit of one selected text.
            //Output is written just on terminal.
            else if(generalMenuOption == 2){
                //Manuel option menu gets text number and bit number(in terms of order)
                ManuelOptionMenu();

                //Find the selected line
                int count = 1;
                while(count != textnumber){
                    line = buffer.readLine();
                    count++;
                }

                //Get the related key text and plain text
                String[] parts = line.split(" ");
                keyTxt = parts[0];
                plainTxt = parts[1];

                //Convert hex plain text into bits
                bitStringOfPlainText = StringToBit(plainTxt);
                //Change one selected bit from plain text
                changedStringInBits = ChangeBit(bitStringOfPlainText, bitnumber);

                //Convert changed plain text which is string format with bits to hex format
                byte[] bconvert = new BigInteger(changedStringInBits, 2).toByteArray();
                byte[] b = new byte[16];
                if(bconvert.length == 17){
                    for(int i = 0; i < 16; i++){
                        b[i] = bconvert[i+1] ;
                    }
                }
                else{
                    b = bconvert;
                }
                changedText = Util.toHEX1(b);

                //Print out on terminal
                System.out.println("Plain text(not changed one): " + plainTxt);
                System.out.println("Changed text(one selected bit is changed): " + changedText);

                //Encrypt Plain Text and print out
                aes.setKey(Util.hex2byte(keyTxt));
                byte[] plainTextBytes =  Util.hex2byte(plainTxt);
                byte[] plainTextEncrypted = aes.encrypt(plainTextBytes);
                System.out.println("Plain Text Encrypted:");
                System.out.println(Util.toHEX(plainTextEncrypted));

                //Encrypt Changed Text and print out
                byte[] changedTextBytes =  Util.hex2byte(changedText);
                byte[] changedTextEncrypted = aes.encrypt(changedTextBytes);
                System.out.println("Changed Text Encrypted:");
                System.out.println(Util.toHEX(changedTextEncrypted));

                //Calculate the bit difference between cipher text which use normal plaintext and one bit changed plaintext
                //And print out.
                double difference = PercentageOfDifference(Util.toHEX1(plainTextEncrypted), Util.toHEX1(changedTextEncrypted));
                System.out.println("Number of flipped bits: " + numOfChangedBits);
                System.out.println("Percentage of difference: " + difference);

                //Clear variable
                changedText = "";
            }

            //Option 3: Exit.
            else if(generalMenuOption == 3){
                break;
            }

            //Choose correct option number
            else{
                System.out.println("You can choose only option 1, 2, 3 or 11.");
            }

            RefreshAllVariables(); //Clear variables
            GeneralMenu(); //General menu
            buffer.close(); //Buffer is closed
        }while(generalMenuOption != 3);

        System.out.println("\n\nTHE END OF AES DIFFUSION ANALYSIS PROGRAMME\n");
    }


    // This is the general menu which is asked before all the progress.
    private static void GeneralMenu(){
        Scanner scan = new Scanner(System.in);
        System.out.println("\n\nPlease select an option:\n" +
                "\t1:  One random bit is selected from each plain text and all texts are encrypted.\n" +
                "\t    The consequences are reported in the text file \"data.txt\".\n" +
                "\t2:  Analyze one text manually.\n" +
                "\t3:  Quit\n" +
                "\t11: (optional) One random bit is selected from each KEY text and all texts are encrypted.\n" +
                "\t    The consequences are reported in the text file \"changedKey.txt\".\n");
        System.out.print("Menu Option:");
        generalMenuOption =  scan.nextInt();
        System.out.println("\n");
    }


    //This menu is asking text number and bit number manually.
    //The menu is used after choosing second option of the general menu.
    //If there is unacceptable answer, related question is re-asked.
    private static void ManuelOptionMenu(){
        Scanner scan = new Scanner(System.in);
        System.out.print("\n\nPlease write the number which text you choose(between 1 - 100)\n" +
                "Text No: ");
        textnumber =  scan.nextInt();
        while(textnumber < 1 || textnumber > 100){
            System.out.println("Error! Please write text number between 1 and 100.\n" +
                    "Text No: ");
            textnumber =  scan.nextInt();
        }
        System.out.print("Please write the bit index which you want to change(between 0 - 127)\n" +
                "Bit No: ");
        bitnumber =  scan.nextInt();
        while(bitnumber < 0 || bitnumber > 127){
            System.out.println("Error! Please write bit number between 0 and 127.\n" +
                    "Bit No: ");
            bitnumber =  scan.nextInt();
        }
    }


    //To change given bit from given text
    private static String ChangeBit(String bitText, int index){
        char c = bitText.charAt(index);
        if(c == '0')
            bitText = bitText.substring(0,index)+"1"+bitText.substring(index+1,128);
        else
            bitText = bitText.substring(0,index)+"0"+bitText.substring(index+1,128);
        return bitText;
    }


    //To change random bit from given text
    private static String ChangeBitRandomly(String bitText){
        Random r = new Random();
        randomIndex = r.nextInt(127);
        char c = bitText.charAt(randomIndex);
        if(c == '0')
            bitText = bitText.substring(0,randomIndex)+"1" + bitText.substring(randomIndex+1,128);
        else
            bitText = bitText.substring(0, randomIndex) + "0" + bitText.substring(randomIndex + 1, 128);
        return bitText;
    }


    //Convert hexadecimal text to bit text
    private static String StringToBit(String plaintext){
        StringBuilder bitsOfWholeString = new StringBuilder();
        char oneDigitOfPlainTxt;
        int intValueOfHexChar;
        if (Util.isHex(plaintext)) {
            for (int i = 0; i < plaintext.length(); i++) {
                oneDigitOfPlainTxt = plaintext.charAt(i);
                intValueOfHexChar = Util.hexDigit(oneDigitOfPlainTxt);
                String bitString = Integer.toBinaryString(intValueOfHexChar);
                if (bitString.length() < 4) {
                    StringBuilder padding = new StringBuilder();
                    for (int k = bitString.length(); k < 4; k++)
                        padding.append("0");
                    bitString = padding + bitString;
                }
                bitsOfWholeString.append(bitString);
            }
        }
        return bitsOfWholeString.toString();
    }


    //Calculate number of different bits between two texts
    private static double PercentageOfDifference(String normalTxt, String changedText){
        String bitStringOfEncryptedPlainText = StringToBit(normalTxt);
        String bitStringOfEncryptedChangedText = StringToBit(changedText);
        numOfChangedBits = 0;
        for(int i = 0; i < bitStringOfEncryptedPlainText.length(); i++){
            if(bitStringOfEncryptedPlainText.charAt(i) != bitStringOfEncryptedChangedText.charAt(i))
                numOfChangedBits++;
        }
        return (double)(100 * numOfChangedBits) / (double)128;
    }


    //Print out text format for one text encryption process(for terminal)
    private static String format1(String plaintext, int index, int flipBitsNum,
                                  String changedText, String cipherText,
                                  String changedCipherText, double percentage){
        return  "Plaintext:\t\t\t\t\t" + plaintext +
                "\nFlip bit:\t\t\t\t\t" + index +
                "\nNew Plaintext:\t\t\t\t" + changedText +
                "\nCiphertext:\t\t\t\t\t" + cipherText +
                "\nNew Ciphertext:\t\t\t\t" + changedCipherText +
                "\nNumber of flipped bits:\t\t" + flipBitsNum +
                "\nPercentage of changed bits:\t" + percentage +
                "\n\n";
    }


    //Print out text format for one text encryption process(for text file)
    private static String format2(String plaintext, int index, int flipBitsNum, double percentage){
        return plaintext + "\t" + index + "\t\t" + flipBitsNum + "\t\t\t" + percentage + "\n";
    }


    // Since I use encryption functions again and again over the menu,
    // I have to clear all selected and calculated variables in order not to do mistakes.
    // Variables can be erased manually, but this is exact solution and kind of precaution.
    private static void RefreshAllVariables(){
        generalMenuOption = 0;
        textnumber = 0;
        bitnumber = 0;
        randomIndex = 0;
        numOfChangedBits = 0;
    }
}
