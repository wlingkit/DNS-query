package ca.ubc.cs.cs317.dnslookup;

import java.util.*;



public class DNSResponse extends DNSQuery{
    
    public static List<HashMap<String, String>> A_info = new ArrayList<HashMap<String, String>>();
    public static List<HashMap<String, String>> AAAA_info = new ArrayList<HashMap<String, String>>();
    public static List<HashMap<String, String>> NS_info = new ArrayList<HashMap<String, String>>();
    public static List<HashMap<String, String>> CNAME_info = new ArrayList<HashMap<String, String>>();
    public static List<HashMap<String, String>> MX_info = new ArrayList<HashMap<String, String>>();
    public static List<HashMap<String, String>> SOA_info = new ArrayList<HashMap<String, String>>();
    public static List<HashMap<String, String>> OTHER_info = new ArrayList<HashMap<String, String>>();

    // Keep track if server is authoritative
    public static boolean is_AA = false; 
    private static int hexStr_bytePointer = 0;

    public static void decoding(String message){
        hexStr_bytePointer = 0;
        
        int ID_OFFSET = 0;
        hexStr_bytePointer+=4;

        int QR_OFFSET = 4;
        // aa is at index 5 in the 16 bits
        // TODO figure out if server is authoritative 
        String QRStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
        int QRInt = Integer.parseInt(QRStr, 16);
        String QRBinary = Integer.toBinaryString(QRInt); 
        char is_authoritative = QRBinary.charAt(5);
        if(is_authoritative == '1'){
            is_AA = true;
        }        
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
        }
        // Shifting byte after getting "00"
        hexStr_bytePointer+=2;

        int QTYPE_OFFSET;
        hexStr_bytePointer+=4;

        int QCLASS_OFFSET;
        hexStr_bytePointer+=4;


        System.out.println(String.format("Nameservers (%o)", name_server_count));
        for(int ns=0; ns < name_server_count; ns++){
            HashMap<String, String> nameServerInfo = new HashMap<String, String>();
            // Common things of the two
            // Name server
            String qname = "";
            hexStr_bytePointer+=2;
            String qnamepointerStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
            int qnamepointer = Integer.parseInt(qnamepointerStr, 16)*2;
            qname = pointerString(qnamepointer, message, qname);
            qname = qname.substring(0, qname.length() - 1);
            nameServerInfo.put("qname", qname);
            hexStr_bytePointer+=2;

            // Type
            String typeStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int typeInt = Integer.parseInt(typeStr, 16);
            String recordType = Integer.toString(typeInt);
            nameServerInfo.put("type", recordType);
            hexStr_bytePointer += 4;

            // Class
            String classStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int classInt = Integer.parseInt(classStr, 16);
            nameServerInfo.put("class", Integer.toString(classInt));
            hexStr_bytePointer += 4;


            // TTL
            String TTLStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+8);
            int TTLInt = Integer.parseInt(TTLStr, 16);
            nameServerInfo.put("TTL", Integer.toString(TTLInt));
            hexStr_bytePointer += 8;

            // RLength
            String RLengthStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int RLength = Integer.parseInt(RLengthStr, 16);
            hexStr_bytePointer += 4;

            // RData
            String Rdata = "";
            if(recordType.equals("2") || recordType.equals("5")){
                // IF TYPE NS OR CNAME
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
            } else if(recordType.equals("1")){
                // IF TYPE A
                for(int j=0; j < RLength; j++){
                    String datatempStr =  message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
                    int number = Integer.parseInt(datatempStr, 16);
                    Rdata += number + ".";
                    hexStr_bytePointer+=2;
                }
            }
            
            // Removing extra "."
            Rdata = Rdata.substring(0, Rdata.length() - 2);
            nameServerInfo.put("Rdata", Rdata);

            // Put each type in different list
            // Type A
            switch(nameServerInfo.get("type")){
                // Type A
                case "1":
                    A_info.add(nameServerInfo);
                    break;
                // Type NS
                case "2":
                    NS_info.add(nameServerInfo);
                    break;
                // Type CNAME
                case "5":
                    CNAME_info.add(nameServerInfo);
                    break;
                // TYPE SOA
                case "6":
                    SOA_info.add(nameServerInfo);
                    break;
                // Type MX
                case "15":
                    MX_info.add(nameServerInfo);
                    break;
                // Type AAAA
                case "28":
                    AAAA_info.add(nameServerInfo);
                    break;
                // Type OTHER
                case "0":
                    OTHER_info.add(nameServerInfo);
                    break;
            }
            System.out.println("    " + nameServerInfo.get("qname") + " " + RecordType.getByCode(Integer.parseInt(nameServerInfo.get("type"))) + " " + nameServerInfo.get("class") + " " + nameServerInfo.get("TTL") + " " + nameServerInfo.get("Rdata"));
            
        }

        System.out.println(String.format("Additional Information (%o)", additional_record_count));
        for(int aa=0; aa < additional_record_count; aa++){
            HashMap<String, String> additionalInfo = new HashMap<String, String>();
            // Common things of the two
            // Name server
            // at 181 OFF SET
            // CHECK IF IT HAS C0 OR NOT
            String qname = "";
            String qnameStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);   
            if(qnameStr.equals("C0")){
                hexStr_bytePointer+=2;
                String qnamepointerStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
                int qnamepointer = Integer.parseInt(qnamepointerStr, 16)*2;
                qname = pointerString(qnamepointer, message, qname);
                qname = qname.substring(0, qname.length() - 1);
            } else {
                int qnameStrLength = Integer.parseInt(qnameStr, 16);
                for(int i=0; i<qnameStrLength;i++){
                    hexStr_bytePointer+=2;
                    String qnameTempStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
                    String letter = ByteHelper.hexToAscii(qnameTempStr);
                    qname+=letter;
                }
                hexStr_bytePointer+=2;
                String qnamepointerStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
                int qnamepointer = Integer.parseInt(qnamepointerStr, 16)*2;
                qname += pointerString(qnamepointer, message, qname);
                qname = qname.substring(0, qname.length() - 1);
                hexStr_bytePointer+=2;
            }
            
            additionalInfo.put("qname", qname);
            hexStr_bytePointer+=2;

            // Type
            // At 183 OFF SET
            String typeStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int typeInt = Integer.parseInt(typeStr, 16);
            String recordType = Integer.toString(typeInt);
            additionalInfo.put("type", recordType);
            hexStr_bytePointer += 4;

            // Class
            String classStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);   
            int classInt = Integer.parseInt(classStr, 16);
            additionalInfo.put("class", Integer.toString(classInt));
            hexStr_bytePointer += 4;


            // TTL
            String TTLStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+8);
            // TODO ERROR FOUND HERE
            int TTLInt = Integer.parseInt(TTLStr, 16);
            additionalInfo.put("TTL", Integer.toString(TTLInt));
            hexStr_bytePointer += 8;

            // RLength
            String RLengthStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int RLength = Integer.parseInt(RLengthStr, 16);
            hexStr_bytePointer += 4;


            // RData TODO 
            // If IPv4 
            String Rdata = "";  
            if(recordType.equals("1")){  
                for(int j=0; j < RLength; j++){
                    String datatempStr =  message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
                    int number = Integer.parseInt(datatempStr, 16);
                    Rdata += number + ".";
                    hexStr_bytePointer+=2;
                }
            } else if(recordType.equals("28")){
                // If IPv6
                // RLength is cut in half because IPv6 is read every four bits
                for(int k=0; k < RLength/2; k++){                   
                    // read every 4 index
                    String datatempStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
                    // remove leading zeros
                    String number = datatempStr.replaceFirst("^0+(?!$)", "");
                    // make sure 0 is kept 
                    Rdata += number + ":";
                    hexStr_bytePointer+=4;
                }
            } else if(recordType.equals("2") || recordType.equals("5")){
                // If CNAME
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
                Rdata = Rdata.substring(0, Rdata.length() - 1);
            }

            Rdata = Rdata.substring(0, Rdata.length() - 1);
            additionalInfo.put("Rdata", Rdata);
            

            // Put each type in different list
            // Type A
            switch(additionalInfo.get("type")){
                // Type A
                case "1":
                    A_info.add(additionalInfo);
                    break;
                // Type NS
                case "2":
                    NS_info.add(additionalInfo);
                    break;
                // Type CNAME
                case "5":
                    CNAME_info.add(additionalInfo);
                    break;
                // TYPE SOA
                case "6":
                    SOA_info.add(additionalInfo);
                    break;
                // Type MX
                case "15":
                    MX_info.add(additionalInfo);
                    break;
                // Type AAAA
                case "28":
                    AAAA_info.add(additionalInfo);
                    break;
                // Type OTHER
                case "0":
                    OTHER_info.add(additionalInfo);
                    break;
            }       

            System.out.println("    " + additionalInfo.get("qname") + " " + RecordType.getByCode(Integer.parseInt(additionalInfo.get("type")))  + " " + additionalInfo.get("class") + " " + additionalInfo.get("TTL") + " " + additionalInfo.get("Rdata"));            

        }
            
    }

    private static String pointerString(int pointer, String message, String pointerMessage){
        // Compressed_pointer is passed into this and read as a pointer instead of the amount of letter  
        String termamountStr = message.substring(pointer, pointer+2);
        int termAmount = Integer.parseInt(termamountStr, 16);
        
        // Base case. When you get "00"
        if(termamountStr.equals("C0")){
            pointer += 2;
            String pointStr = message.substring(pointer, pointer+2);
            int pointTo = Integer.parseInt(pointStr, 16)*2;
            return pointerString(pointTo, message, pointerMessage);
        }

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

    private static void get_NS_CNAME(int RLength, int pointer, String Rdata){
        for(int j=0; j < RLength; j++){
            String datatempStr =  message.substring(pointer, pointer+2);
            int datatempInt = Integer.parseInt(datatempStr, 16);

            // CASE ONE where theres a pointer(compressed message)
            if(datatempStr.equals("C0")){
                pointer+=2;
                String RdatapointerStr = message.substring(pointer, pointer+2);
                int Rdatapointer = Integer.parseInt(RdatapointerStr, 16)*2;  

                Rdata = pointerString(Rdatapointer, message, Rdata);
                pointer+=2;
                j+=4;
            } else {

            // CASE TWO where theres no pointer 
                for(int k=0; k < datatempInt; k++){
                    pointer+=2;
                    j++;
                    datatempStr = message.substring(pointer, pointer+2);
                    String letter = ByteHelper.hexToAscii(datatempStr);
                    Rdata += letter;
                }
                
                // Onto the next word
                pointer+=2;
            }
            Rdata += ".";
            
        }
        hexStr_bytePointer = pointer;
    }

}