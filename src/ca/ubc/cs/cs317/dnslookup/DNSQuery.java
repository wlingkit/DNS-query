package ca.ubc.cs.cs317.dnslookup;

import java.util.*;



public class DNSQuery{
    
    private static Random random = new Random();
    public static String rand_id = "";
    public static String query_parameters = "";
    public static String num_of_questions = "0001";
    public static String num_of_answers = "0000";
    public static String authority_records = "0000";
    public static String additional_records = "0000";
    public static String qnameStr = "";
    public static String message = "";
    public static String qtype = "";

       // Encoding message for send up
    // Message structure: message = "AA AA |01 00           |  00 01  | 00 00 |00 00            |00 00              |07 65 78 61 6d 70 6c 65 03 63 6f 6d 00| 00 01| 00 01"
    //                               ID    |Query parameters|#question|#answer|authority records|additional records |qname                                 |qtype |qclass
    //                              Same   |
    // Query parameters: QR (1bit) = 0 because its a query. Opcode (4bits) = 0 because its a standard query
    // AA (1) = 0. TC (1) = 0 for not trucating message. RD (1) = 0 because we dont want recursion. RA (1) = 0. Z (3) = 000. RCODE (4) = 0000
    // AAAA     00000000 0001       0000    0000 0000 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 0001     0001
    
    // Same     Same     Changes    Changes same same changes                  changes  same
    public static byte[] encoding(DNSNode node){
        // byte[] test_byte = {0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01};
        // byte[] test_byte = {0x12, 0x12, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01};
        
        // ID - two bytes [ID][ID]
        // Randomly generate two bytes for the unique id
        byte[] rand_byte = new byte[2];
        random.nextBytes(rand_byte);
        rand_id = ByteHelper.bytesToHex(rand_byte);
        
        // Query parameters - two bytes [QR, Opcode, AA, TC, RD][RA, Z, RCODE]
        // Every four binary into one hexadecimal. 8 binaries into one byte 
        query_parameters = "0000";

        // Number of questions - two bytes [00][01]
        // num_of_questions = "0001";

        // Number of answers - two bytes [00][00]
        // num_of_answers = "0000";

        // Authority records - two bytes [00][00]
        // authority_records = "0000";

        // Additional records - two bytes [00][00]
        // additional_records = "0000";

        // Qname - Enough for name. Convert each letter to hex by itself
        qnameStr = node.getHostName();
        // Split qname by "."
        String[] qnameArray = qnameStr.split("\\.");

        // Getting the length of qname encoding
        // Start counting with the number of words in qname
        int qname_length = qnameArray.length;

        // Getting the number of char in qname 
        for(int i=0; i<qnameArray.length; i++){
            qname_length += qnameArray[i].length();
        }

        String qname = "";
        // Need to add 0 before number of letters
        // need to remove 00x before bytes
        for(int i=0; i < qnameArray.length; i++){
            // Iterating through the string 
            // Converting the number of chars in a word into hex and byte
            String amount_hexStr = "0" + Integer.toHexString(qnameArray[i].length());
            qname += amount_hexStr;

            for(int j=0; j < qnameArray[i].length(); j++){
                // Getting each letter in a string by converting it to hex and then to byte
                // Then place byte into byte array
                char c = qnameArray[i].charAt(j);
                String char_hexStr = String.format("%x", (int) c);
                qname += char_hexStr;
            }
        }
        // Ending qname
        qname += "00";

        // Qtype - two bytes [00][.getType]
        String qtype_hexStr = qtype_encode(node);
        
        if(qtype_hexStr.length() == 1){
            qtype += "000" + qtype_hexStr;
        } else if(qtype_hexStr.length() == 2){
            qtype += "00" + qtype_hexStr;
        }

        // Qclass - two bytes [00][01]
        String qclass = "0001";

        // Figure out now many bytes you need 16 + qname every letter is a byte
        message = rand_id + query_parameters + num_of_questions + num_of_answers + authority_records + additional_records + qname + qtype + qclass;
        byte[] message_byteArray = ByteHelper.hexStringToByteArray(message);

        // String message = id_str + query_parameters + num_question + num_answer + authority_record + additional_record + qname + qtype + qclass;
        return message_byteArray;
    }



    

    private static String qtype_encode(DNSNode node){
        int type = node.getType().getCode();
        String hex_string = Integer.toHexString(type);

        return hex_string;
    }


    
}