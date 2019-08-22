package ca.ubc.cs.cs317.dnslookup;

import java.util.*;



public class DNSResponse extends DNSQuery{
    static int hexStr_bytePointer = 0;  
    //Decoding message 
    //Have a global variable to indicate where you are
    // -------------Question------------
        // 3322800000010000000D000E06676F6F676C6503636F6D0000010001 <- BYTE 28

        // -------------Type NS-------------
        // C013 00020001 0002A300 0014 01610C67746C642D73657276657273036E657400
        // C013 000200010002A30000040162C02A C013000200010002A30000040163C02A C013000200010002A30000040164C02A C013000200010002A30000040165C02A
        // C013000200010002A30000040166C02A C013000200010002A30000040167C02A C013000200010002A30000040168C02A C013000200010002A30000040169C02A 
        // C013000200010002A3000004016AC02A C013000200010002A3000004016BC02A C013000200010002A3000004016CC02A C013000200010002A3000004016DC02A


        // ------------Type A IPv4----------
        // C028000100010002A3000004C005061E C048000100010002A3000004C0210E1E C058000100010002A3000004C01A5C1E C068000100010002A3000004C01F501E
        // C078000100010002A3000004C00C5E1E C088000100010002A3000004C023331E C098000100010002A3000004C02A5D1E C0A8000100010002A3000004C036701E
        // C0B8000100010002A3000004C02BAC1E C0C8000100010002A3000004C0304F1E C0D8000100010002A3000004C034B21E C0E8000100010002A3000004C029A21E
        // C0F8000100010002A3000004C037531E 
        // ------------Type A IPv6----------
        // C028001C00010002A300001020010503A83E00000000000000020030
        
        // Get type, class, TTL
        // Depending on the type for next step:
        // if 01, C0 is not a points and is a number 
        // if 02, C0 is a pointer and end with 00 
    public static void decoding(String message){
        // TODO cant skip. Need to find Number of server name and number of additional info

        int ID_OFFSET = 0;
        hexStr_bytePointer+=4;

        int QR_OFFSET = 4;
        hexStr_bytePointer+=4;

        int QDCOUNT_OFFSET = 8;
        hexStr_bytePointer+=4;

        int ANCOUNT_OFFSET = 12;
        hexStr_bytePointer+=4;

        int NSCOUNT_OFFSET = 16;
        String name_server_countStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
        int name_server_count = Integer.parseInt(name_server_countStr, 16);
        hexStr_bytePointer+=4;

        int ARCOUNT_OFFSET = 20;
        String additional_record_countStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
        int additional_record_count = Integer.parseInt(additional_record_countStr, 16);
        hexStr_bytePointer+=4;

        int QNAME_OFFSET = 24;
        String pointerStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
        while(!pointerStr.equals("00")){
            hexStr_bytePointer+=2;
            pointerStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
            // TODO Print QNAME? 
        }
        // Shifting byte after getting "00"
        hexStr_bytePointer+=2;

        int QTYPE_OFFSET;
        hexStr_bytePointer+=4;

        int QCLASS_OFFSET;
        hexStr_bytePointer+=4;


        HashMap<String, String> decodedInfo = new HashMap<String, String>();
        // Iterating through name servers 
        // The two cases
        // C013 0002 0001 0002A300 0014 0161 0C 67746C642D73657276657273036E657400
        // C013 0002 0001 0002A300 0004 0163 C0 2A
        for(int ns=0; ns < name_server_count; ns++){
            // Common things of the two
            // Name server
            System.out.println("At the start");
            System.out.println(hexStr_bytePointer);
            String qname = "";
            hexStr_bytePointer+=2;
            String qnamepointerStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
            int qnamepointer = Integer.parseInt(qnamepointerStr, 16)*2;
            qname = pointerString(qnamepointer, message, qname);
            qname = qname.substring(0, qname.length() - 1);
            System.out.println(qname);
            System.out.println("qname");
            hexStr_bytePointer+=2;

            // Type
            String typeStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int typeInt = Integer.parseInt(typeStr, 16);
            decodedInfo.put("type", Integer.toString(typeInt));
            hexStr_bytePointer += 4;

            // Class
            String classStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int classInt = Integer.parseInt(classStr, 16);
            decodedInfo.put("class", Integer.toString(classInt));
            hexStr_bytePointer += 4;


            // TTL
            String TTLStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+8);
            int TTLInt = Integer.parseInt(TTLStr, 16);
            decodedInfo.put("TTL", Integer.toString(TTLInt));
            hexStr_bytePointer += 8;

            // RLength
            String RLengthStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int RLength = Integer.parseInt(RLengthStr, 16);
            hexStr_bytePointer += 4;

            // RData
            String Rdata = "";        
            
            for(int j=0; j < RLength; j++){
                String datatempStr =  message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
                int datatempInt = Integer.parseInt(datatempStr, 16);

                // CASE ONE where theres a pointer(compressed message)
                if(datatempStr.equals("C0")){
                    hexStr_bytePointer+=2;
                    String RdatapointerStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
                    int Rdatapointer = Integer.parseInt(RdatapointerStr, 16)*2;  

                    Rdata = pointerString(Rdatapointer, message, Rdata);
                    hexStr_bytePointer+=2;
                    j+=4;
                } else {
                // CASE TWO where theres no pointer 
                // This for loop shouldnt be here as RLength represent all of 20 bytes
                    for(int k=0; k < datatempInt; k++){
                        hexStr_bytePointer+=2;
                        j++;
                        datatempStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
                        String letter = ByteHelper.hexToAscii(datatempStr);
                        Rdata += letter;
                    }
                    
                    // Onto the next word
                    hexStr_bytePointer+=2;
                }
                Rdata += ".";
            }
            // Removing extra "."
            Rdata = Rdata.substring(0, Rdata.length() - 2);
            System.out.println(Rdata);
        }

        // Iterating through additional section
        // ------------Type A IPv4----------
        // C028 0001 0001 0002A300 0004 C005061E
        // ------------Type A IPv6----------
        // C028001C00010002A300001020010503A83E00000000000000020030
        for(int aa=0; aa < additional_record_count; aa++){
            System.out.println("?");
            // Common things of the two
            // Name server
            String qname = "";
            pointerString(hexStr_bytePointer, message, qname);
            hexStr_bytePointer+=4;

            // Type
            String typeStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int typeInt = Integer.parseInt(typeStr, 16);
            decodedInfo.put("type", Integer.toString(typeInt));
            hexStr_bytePointer += 4;

            // Class
            String classStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int classInt = Integer.parseInt(classStr, 16);
            decodedInfo.put("class", Integer.toString(classInt));
            hexStr_bytePointer += 4;


            // TTL
            String TTLStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+8);
            int TTLInt = Integer.parseInt(TTLStr, 16);
            decodedInfo.put("TTL", Integer.toString(TTLInt));
            hexStr_bytePointer += 8;

            // RLength
            String RLengthStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int RLength = Integer.parseInt(RLengthStr, 16);
            hexStr_bytePointer += 4;

            // RData
            String Rdata = "";            
            for(int j=0; j < RLength; j++){
                String datatempStr =  message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
                int datatempInt = Integer.parseInt(datatempStr, 16);

                // Only one case
                 for(int k=0; k < datatempInt; k++){
                     hexStr_bytePointer+=2;
                     datatempStr =  message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
                     String letter = ByteHelper.hexToAscii(datatempStr);
                     Rdata += letter;
                }
                // Onto the next word
                hexStr_bytePointer+=2;
                }
                
            }
        }

    private static String pointerString(int pointer, String message, String pointerMessage){
        // Compressed_pointer is passed into this and read as a pointer instead of the amount of letter  
        
        String termamountStr = message.substring(pointer, pointer+2);
        int termAmount = Integer.parseInt(termamountStr, 16);
        System.out.println(termamountStr.equals("00"));
        System.out.println(termAmount);
        
        // Base case. When you get "00"
        if(termamountStr.equals("00")){           
            return pointerMessage;
        } 
    
        for(int i=0; i < termAmount; i++){
            pointer += 2;
            String hexletterStr = message.substring(pointer, pointer+2);
            String letter = ByteHelper.hexToAscii(hexletterStr);
            pointerMessage += letter;       
        }
            
        pointerMessage+=".";
        pointer += 2;
        return pointerString(pointer, message, pointerMessage);
    }

}