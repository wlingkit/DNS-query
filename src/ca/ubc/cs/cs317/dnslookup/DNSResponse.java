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
    

    public static List<HashMap<String, String>> answerRecord = new ArrayList<HashMap<String, String>>();
    public static List<HashMap<String, String>> nameServerRecord = new ArrayList<HashMap<String, String>>();
    public static List<HashMap<String, String>> additionalRecord = new ArrayList<HashMap<String, String>>();
    public static List<HashMap<String, String>> authoritativeAnswers = new ArrayList<HashMap<String, String>>();

    // Keep track if server is authoritative
    public static boolean is_AA = false; 
    public static int numAnswer;
    public static int numNameServer;
    public static int numAdditionalRecord;

    // OFFSETS
    private static int globalPointer = 0;
    private static int[] recordAmount = new int[3];


    private static int READING_OFFSET = 2;
    private static int ID_OFFSET = 4;
    private static int QR_OFFSET = 4;
    private static int QDCOUNT_OFFSET = 4;
    private static int ANCOUNT_OFFSET = 4;
    private static int NSCOUNT_OFFSET = 4;
    private static int ARCOUNT_OFFSET = 4;
    private static int QTYPE_OFFSET = 4;
    private static int QCLASS_OFFSET = 4;
    private static int TYPE_OFFSET = 4;
    private static int CLASS_OFFSET = 4;
    private static int TTL_OFFSET = 8;
    private static int RLENGTH_OFFSET = 4;
    

    public static void decoding(String message){
        
        globalPointer = 0;
        
        globalPointer+=ID_OFFSET;

        // aa is at index 5 in the 16 bits
        is_AA = is_authoritative(globalPointer, message);
        globalPointer+=QR_OFFSET;

        // Number of questions
        globalPointer+=QDCOUNT_OFFSET;

        // Number of answers
        
        String numAnswerStr = message.substring(globalPointer, globalPointer+4);
        numAnswer = Integer.parseInt(numAnswerStr, 16);
        recordAmount[0] = numAnswer;
        System.out.println("numAnswer: "+ numAnswer);
        globalPointer+=ANCOUNT_OFFSET;

        // Number of name servers
        
        String numNameServerStr = message.substring(globalPointer, globalPointer+4);
        numNameServer = Integer.parseInt(numNameServerStr, 16);
        recordAmount[1] = numNameServer;
        globalPointer+=NSCOUNT_OFFSET;
        System.out.println("numNameServer: "+ numNameServer);

        // Number of additional records
        
        String numAdditionalRecordStr = message.substring(globalPointer, globalPointer+4);
        numAdditionalRecord = Integer.parseInt(numAdditionalRecordStr, 16);
        recordAmount[2] = numAdditionalRecord;
        System.out.println("numAdditionalRecord: "+ numAdditionalRecord);
        globalPointer+=ARCOUNT_OFFSET;

        String pointerStr = message.substring(globalPointer, globalPointer+2);
        while(!pointerStr.equals("00")){
            globalPointer+=READING_OFFSET;
            pointerStr = message.substring(globalPointer, globalPointer+2);
        }
        // Shifting byte after getting "00"
        globalPointer+=READING_OFFSET;

        globalPointer+=QTYPE_OFFSET;

        globalPointer+=QCLASS_OFFSET;
        
        for(int section=0; section < 3; section++){
            for(int record=0; record < recordAmount[section]; record++){
                resolveRecord(message, section);
            }       
        }
        // for(int a=0; a< numAnswer; a++){
        //     System.out.println("-------------------Check point a------------------------");
        //     HashMap<String, String> answerInfo = new HashMap<String, String>();
        //     // Common things of the two
        //     // Name server
            
        //     globalPointer+=2;
        //     String qname = "";
        //     String qnamepointerStr = message.substring(globalPointer, globalPointer+2);
        //     int qnamepointer = Integer.parseInt(qnamepointerStr, 16)*2;
        //     qname = compressedReferece(qnamepointer, message, qname);
        //     qname = qname.substring(0, qname.length() - 1);
        //     answerInfo.put("qname", qname);
        //     globalPointer+=READING_OFFSET;
        //     System.out.println("-------------------Check point b------------------------");
        //     // Type
        //     String typeStr = message.substring(globalPointer, globalPointer+4);
        //     int typeInt = Integer.parseInt(typeStr, 16);
        //     String recordType = Integer.toString(typeInt);
        //     answerInfo.put("type", recordType);
        //     globalPointer += TYPE_OFFSET;
        //     System.out.println("-------------------Check point c------------------------");
        //     // Class
        //     String classStr = message.substring(globalPointer, globalPointer+4);
        //     int classInt = Integer.parseInt(classStr, 16);
        //     answerInfo.put("class", Integer.toString(classInt));
        //     globalPointer += CLASS_OFFSET;
        //     System.out.println("-------------------Check point d------------------------");

        //     // TTL
        //     String TTLStr = message.substring(globalPointer, globalPointer+8);
        //     int TTLInt = Integer.parseInt(TTLStr, 16);
        //     answerInfo.put("TTL", Integer.toString(TTLInt));
        //     globalPointer += TTL_OFFSET;
        //     System.out.println("-------------------Check point e------------------------");

        //     // RLength
        //     String RLengthStr = message.substring(globalPointer, globalPointer+4);
        //     int RLength = Integer.parseInt(RLengthStr, 16);
        //     globalPointer += RLENGTH_OFFSET;
        //     System.out.println("-------------------Check point f------------------------");

        //     // RData
        //     String Rdata = "";
        //     if(recordType.equals("2") || recordType.equals("5")){
        //         // IF TYPE NS OR CNAME
        //         for(int j=0; j < RLength; j++){
        //             String datatempStr =  message.substring(globalPointer, globalPointer+2);
        //             int datatempInt = Integer.parseInt(datatempStr, 16);
    
        //             // CASE ONE where theres a pointer(compressed message)
        //             if(datatempStr.equals("C0")){
        //                 globalPointer+=2;
        //                 String RdatapointerStr = message.substring(globalPointer, globalPointer+2);
        //                 int Rdatapointer = Integer.parseInt(RdatapointerStr, 16)*2;  
    
        //                 Rdata = compressedReferece(Rdatapointer, message, Rdata);
        //                 Rdata = Rdata.substring(0, Rdata.length() - 1);
        //                 globalPointer+=2;
        //                 j+=4;
        //             } else {
        //             // CASE TWO where theres no pointer 
        //                 for(int k=0; k < datatempInt; k++){
        //                     globalPointer+=2;
        //                     j++;
        //                     datatempStr = message.substring(globalPointer, globalPointer+2);
                            
        //                     String letter = ByteHelper.hexToAscii(datatempStr);
        //                     Rdata += letter;
                            

                            
        //                 }
                        
        //                 // Onto the next word
        //                 globalPointer+=2;
        //             }
        //             Rdata += ".";
        //         }
        //     } else if(recordType.equals("1")){
        //         // IF TYPE A
        //         for(int j=0; j < RLength; j++){
        //             String datatempStr =  message.substring(globalPointer, globalPointer+2);
        //             int number = Integer.parseInt(datatempStr, 16);
        //             Rdata += number + ".";
        //             globalPointer+=2;
        //         }
        //         // Rdata = Rdata.substring(0, Rdata.length() - 1);
        //     } else if(recordType.equals("28")){
        //         // If IPv6
        //         // RLength is cut in half because IPv6 is read every four bits
        //         for(int k=0; k < RLength/2; k++){                   
        //             // read every 4 index
        //             String datatempStr = message.substring(globalPointer, globalPointer+4);
        //             // remove leading zeros
        //             String number = datatempStr.replaceFirst("^0+(?!$)", "");
        //             // make sure 0 is kept 
        //             Rdata += number + ":";
        //             globalPointer+=4;
        //         }
        //     }

        //     System.out.println("-------------------Check point g------------------------");
        //     // Removing extra "."
        //     Rdata = Rdata.substring(0, Rdata.length() - 1);
        //     answerInfo.put("Rdata", Rdata);

        //     // Put each type in different list
        //     // Type A
        //     switch(answerInfo.get("type")){
        //         // Type A
        //         case "1":
        //             A_info.add(answerInfo);
        //             break;
        //         // Type NS
        //         case "2":
        //             NS_info.add(answerInfo);
        //             break;
        //         // Type CNAME
        //         case "5":
        //             CNAME_info.add(answerInfo);
        //             break;
        //         // TYPE SOA
        //         case "6":
        //             SOA_info.add(answerInfo);
        //             break;
        //         // Type MX
        //         case "15":
        //             MX_info.add(answerInfo);
        //             break;
        //         // Type AAAA
        //         case "28":
        //             AAAA_info.add(answerInfo);
        //             break;
        //         // Type OTHER
        //         case "0":
        //             OTHER_info.add(answerInfo);
        //             break;
        //     }
        //     answerRecord.add(answerInfo);
        //     if(is_AA){
        //         authoritativeAnswers.add(answerInfo);
        //     }
                       
        // }
        // System.out.println("-------------------Check point 11------------------------");
        // for(int ns=0; ns < numNameServer; ns++){
        //     HashMap<String, String> nameServerInfo = new HashMap<String, String>();
        //     // Common things of the two
        //     // Name server
        //     String qname = "";
        //     globalPointer+=2;
        //     String qnamepointerStr = message.substring(globalPointer, globalPointer+2);
        //     int qnamepointer = Integer.parseInt(qnamepointerStr, 16)*2;
        //     qname = compressedReferece(qnamepointer, message, qname);
        //     qname = qname.substring(0, qname.length() - 1);
        //     nameServerInfo.put("qname", qname);
        //     globalPointer+=2;

        //     // Type
        //     String typeStr = message.substring(globalPointer, globalPointer+4);
        //     int typeInt = Integer.parseInt(typeStr, 16);
        //     String recordType = Integer.toString(typeInt);
        //     nameServerInfo.put("type", recordType);
        //     globalPointer += 4;

        //     // Class
        //     String classStr = message.substring(globalPointer, globalPointer+4);
        //     int classInt = Integer.parseInt(classStr, 16);
        //     nameServerInfo.put("class", Integer.toString(classInt));
        //     globalPointer += 4;


        //     // TTL
        //     String TTLStr = message.substring(globalPointer, globalPointer+8);
        //     int TTLInt = Integer.parseInt(TTLStr, 16);
        //     nameServerInfo.put("TTL", Integer.toString(TTLInt));
        //     globalPointer += 8;

        //     // RLength
        //     String RLengthStr = message.substring(globalPointer, globalPointer+4);
        //     int RLength = Integer.parseInt(RLengthStr, 16);
        //     globalPointer += 4;

        //     // RData
        //     String Rdata = "";
        //     if(recordType.equals("2") || recordType.equals("5")){
        //         // IF TYPE NS OR CNAME
        //         for(int j=0; j < RLength; j++){
        //             String datatempStr =  message.substring(globalPointer, globalPointer+2);
        //             int datatempInt = Integer.parseInt(datatempStr, 16);
    
        //             // CASE ONE where theres a pointer(compressed message)
        //             if(datatempStr.equals("C0")){
        //                 globalPointer+=READING_OFFSET;
        //                 String RdatapointerStr = message.substring(globalPointer, globalPointer+2);
        //                 int Rdatapointer = Integer.parseInt(RdatapointerStr, 16)*2;  
    
        //                 Rdata = compressedReferece(Rdatapointer, message, Rdata);
        //                 globalPointer+=READING_OFFSET;
        //                 j+=2;
        //             } else {
        //             // CASE TWO where theres no pointer 
        //                 for(int k=0; k < datatempInt; k++){
        //                     globalPointer+=READING_OFFSET;
        //                     j++;
        //                     datatempStr = message.substring(globalPointer, globalPointer+2);
        //                     String letter = ByteHelper.hexToAscii(datatempStr);
        //                     Rdata += letter;
        //                 }
                        
        //                 // Onto the next word
        //                 globalPointer+=2;
        //             }
        //             Rdata += ".";
        //         }
        //     } else if(recordType.equals("1")){
        //         // IF TYPE A
        //         for(int j=0; j < RLength; j++){
        //             String datatempStr =  message.substring(globalPointer, globalPointer+2);
        //             int number = Integer.parseInt(datatempStr, 16);
        //             Rdata += number + ".";
        //             globalPointer+=2;
        //         }
        //     } else if(recordType.equals("28")){
        //         // If IPv6
        //         // RLength is cut in half because IPv6 is read every four bits
        //         for(int k=0; k < RLength/2; k++){                   
        //             // read every 4 index
        //             String datatempStr = message.substring(globalPointer, globalPointer+4);
        //             // remove leading zeros
        //             String number = datatempStr.replaceFirst("^0+(?!$)", "");
        //             // make sure 0 is kept 
        //             Rdata += number + ":";
        //             globalPointer+=4;
        //         }
        //     }
            
        //     // Removing extra "."
        //     Rdata = Rdata.substring(0, Rdata.length() - 2);
        //     nameServerInfo.put("Rdata", Rdata);

        //     // Put each type in different list
        //     // Type A
        //     switch(nameServerInfo.get("type")){
        //         // Type A
        //         case "1":
        //             A_info.add(nameServerInfo);
        //             break;
        //         // Type NS
        //         case "2":
        //             NS_info.add(nameServerInfo);
        //             break;
        //         // Type CNAME
        //         case "5":
        //             CNAME_info.add(nameServerInfo);
        //             break;
        //         // TYPE SOA
        //         case "6":
        //             SOA_info.add(nameServerInfo);
        //             break;
        //         // Type MX
        //         case "15":
        //             MX_info.add(nameServerInfo);
        //             break;
        //         // Type AAAA
        //         case "28":
        //             AAAA_info.add(nameServerInfo);
        //             break;
        //         // Type OTHER
        //         case "0":
        //             OTHER_info.add(nameServerInfo);
        //             break;
        //     }
        //     nameServerRecord.add(nameServerInfo);
            
        // }
        // System.out.println("-------------------Check point 12------------------------");
        // for(int aa=0; aa < numAdditionalRecord; aa++){
        //     System.out.println(aa);
        //     HashMap<String, String> additionalInfo = new HashMap<String, String>();
        //     // Common things of the two
        //     // Name server
        //     // at 181 OFF SET
        //     // CHECK IF IT HAS C0 OR NOT
        //     String qname = "";
        //     String qnameStr = message.substring(globalPointer, globalPointer+2);   
        //     if(qnameStr.equals("C0") || qnameStr.equals("C1") ){
        //         globalPointer+=2;
        //         String qnamepointerStr = message.substring(globalPointer, globalPointer+2);
        //         int qnamepointer = Integer.parseInt(qnamepointerStr, 16)*2;
        //         qname = compressedReferece(qnamepointer, message, qname);
        //         qname = qname.substring(0, qname.length() - 1);
        //     } else {
        //         int qnameStrLength = Integer.parseInt(qnameStr, 16);
        //         for(int i=0; i<qnameStrLength;i++){
        //             globalPointer+=2;
        //             String qnameTempStr = message.substring(globalPointer, globalPointer+2);
        //             String letter = ByteHelper.hexToAscii(qnameTempStr);
        //             qname+=letter;
        //         }
        //         globalPointer+=2;
        //         String qnamepointerStr = message.substring(globalPointer, globalPointer+2);
        //         int qnamepointer = Integer.parseInt(qnamepointerStr, 16)*2;
        //         qname += compressedReferece(qnamepointer, message, qname);
        //         qname = qname.substring(0, qname.length() - 1);
        //         globalPointer+=2;
        //     }
        //     System.out.println("-------------------Check point a------------------------");
        //     additionalInfo.put("qname", qname);
        //     globalPointer+=2;

        //     // Type
        //     // At 183 OFF SET
        //     String typeStr = message.substring(globalPointer, globalPointer+4);
        //     int typeInt = Integer.parseInt(typeStr, 16);
        //     String recordType = Integer.toString(typeInt);
        //     additionalInfo.put("type", recordType);
        //     globalPointer += 4;
        //     System.out.println("-------------------Check point b------------------------");
        //     // Class
        //     String classStr = message.substring(globalPointer, globalPointer+4);   
        //     int classInt = Integer.parseInt(classStr, 16);
        //     additionalInfo.put("class", Integer.toString(classInt));
        //     globalPointer += 4;

        //     System.out.println("-------------------Check point c------------------------");
        //     // TTL
        //     String TTLStr = message.substring(globalPointer, globalPointer+8);
        //     // TODO ERROR FOUND HERE
        //     int TTLInt = Integer.parseInt(TTLStr, 16);
        //     additionalInfo.put("TTL", Integer.toString(TTLInt));
        //     globalPointer += 8;
        //     System.out.println("-------------------Check point d------------------------");
        //     // RLength
        //     String RLengthStr = message.substring(globalPointer, globalPointer+4);
        //     int RLength = Integer.parseInt(RLengthStr, 16);
        //     globalPointer += 4;

        //     System.out.println("-------------------Check point e------------------------");
        //     // RData TODO 
        //     // If IPv4 
        //     String Rdata = "";  
        //     if(recordType.equals("2") || recordType.equals("5")){
        //         // IF TYPE NS OR CNAME
        //         for(int j=0; j < RLength; j++){
        //             String datatempStr =  message.substring(globalPointer, globalPointer+2);
        //             int datatempInt = Integer.parseInt(datatempStr, 16);
    
        //             // CASE ONE where theres a pointer(compressed message)
        //             if(datatempStr.equals("C0")){
        //                 globalPointer+=READING_OFFSET;
        //                 String RdatapointerStr = message.substring(globalPointer, globalPointer+2);
        //                 int Rdatapointer = Integer.parseInt(RdatapointerStr, 16)*2;  
    
        //                 Rdata = compressedReferece(Rdatapointer, message, Rdata);
        //                 globalPointer+=READING_OFFSET;
        //                 Rdata = Rdata.substring(0, Rdata.length() - 1);
        //                 j+=2;
        //             } else {
        //             // CASE TWO where theres no pointer 
        //                 for(int k=0; k < datatempInt; k++){
        //                     globalPointer+=READING_OFFSET;
        //                     j++;
        //                     datatempStr = message.substring(globalPointer, globalPointer+2);
        //                     String letter = ByteHelper.hexToAscii(datatempStr);
        //                     Rdata += letter;
        //                 }
                        
        //                 // Onto the next word
        //                 globalPointer+=2;
        //             }
        //             Rdata += ".";
        //         }
        //     } else if(recordType.equals("1")){
        //         // IF TYPE A
        //         for(int j=0; j < RLength; j++){
        //             String datatempStr =  message.substring(globalPointer, globalPointer+2);
        //             int number = Integer.parseInt(datatempStr, 16);
        //             Rdata += number + ".";
        //             globalPointer+=2;
        //         }
        //     } else if(recordType.equals("28")){
        //         // If IPv6
        //         // RLength is cut in half because IPv6 is read every four bits
        //         for(int k=0; k < RLength/2; k++){                   
        //             // read every 4 index
        //             String datatempStr = message.substring(globalPointer, globalPointer+4);
        //             // remove leading zeros
        //             String number = datatempStr.replaceFirst("^0+(?!$)", "");
        //             // make sure 0 is kept 
        //             Rdata += number + ":";
        //             globalPointer+=4;
        //         }
        //     }
          
        //     System.out.println("-------------------Check point j------------------------");
        //     System.out.println(Rdata);
        //     if(Rdata.length() >= 1){
        //         System.out.println("In Rdata if");
        //         Rdata = Rdata.substring(0, Rdata.length() - 1);
        //     }
            
        //     System.out.println("below Rdata");
        //     additionalInfo.put("Rdata", Rdata);
            

        //     // Put each type in different list
        //     // Type A
        //     switch(additionalInfo.get("type")){
        //         // Type A
        //         case "1":
        //             A_info.add(additionalInfo);
        //             break;
        //         // Type NS
        //         case "2":
        //             NS_info.add(additionalInfo);
        //             break;
        //         // Type CNAME
        //         case "5":
        //             CNAME_info.add(additionalInfo);
        //             break;
        //         // TYPE SOA
        //         case "6":
        //             SOA_info.add(additionalInfo);
        //             break;
        //         // Type MX
        //         case "15":
        //             MX_info.add(additionalInfo);
        //             break;
        //         // Type AAAA
        //         case "28":
        //             AAAA_info.add(additionalInfo);
        //             break;
        //         // Type OTHER
        //         case "0":
        //             OTHER_info.add(additionalInfo);
        //             break;
        //     }       
        //     additionalRecord.add(additionalInfo);
            
        // }
    }

    private static String compressedReferece(int pointer, String message, String pointerMessage){
        // Compressed_pointer is passed into this and read as a pointer instead of the amount of letter  
        String termamountStr = message.substring(pointer, pointer+2);
        int termAmount = Integer.parseInt(termamountStr, 16);
        
        

        if(termamountStr.equals("C0")){
            pointer += 2;
            String pointStr = message.substring(pointer, pointer+2);
            int pointTo = Integer.parseInt(pointStr, 16)*2;
            return compressedReferece(pointTo, message, pointerMessage);
        }

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
        return compressedReferece(pointer, message, pointerMessage);
    }

    private static boolean is_authoritative(int pointer, String response){
        String QRStr = response.substring(globalPointer, globalPointer+4);
        int QRInt = Integer.parseInt(QRStr, 16);
        String QRBinary = Integer.toBinaryString(QRInt); 
        char is_authoritative = QRBinary.charAt(5);
        if(is_authoritative == '1'){
            return true;
        } else {
            return false;
        }       
    }


    // Responsible for calling resolve functions and saving data 
    private static void resolveRecord(String response, int answerSection){
        HashMap<String, String> decordedRecord = new HashMap<String, String>();
        // qname
        String qname = resolveQNAME(globalPointer, response);
        decordedRecord.put("qname", qname);
        // Type
        String recordType = resolveTYPE(globalPointer, response);
        decordedRecord.put("type", recordType);
        // Class
        String recordClass = resolveCLASS(globalPointer, response);
        decordedRecord.put("class", recordClass);
        // TTL
        String TTL = resolveTTL(globalPointer, response);
        decordedRecord.put("TTL", TTL);
        // Rdata
        String Rdata = resolveRDATA(globalPointer, response, recordType);
        decordedRecord.put("Rdata", Rdata);
        switch(answerSection){
            case 0:
                answerRecord.add(decordedRecord);
                if(is_AA){
                    authoritativeAnswers.add(decordedRecord);
                }
                break;
            case 1:
                nameServerRecord.add(decordedRecord);
                break;
            case 2:
                additionalRecord.add(decordedRecord);
                break;
            default:
                System.err.println("Incorrect integer recieved. Should be between 0 and 3.");
                throw new RuntimeException("Incorrect integer recieved.");
        }
        switch(decordedRecord.get("type")){
                    // Type A
                    case "1":
                        A_info.add(decordedRecord);
                        break;
                    // Type NS
                    case "2":
                        NS_info.add(decordedRecord);
                        break;
                    // Type CNAME
                    case "5":
                        CNAME_info.add(decordedRecord);
                        break;
                    // TYPE SOA
                    case "6":
                        SOA_info.add(decordedRecord);
                        break;
                    // Type MX
                    case "15":
                        MX_info.add(decordedRecord);
                        break;
                    // Type AAAA
                    case "28":
                        AAAA_info.add(decordedRecord);
                        break;
                    // Type OTHER
                    case "0":
                        OTHER_info.add(decordedRecord);
                        break;
        }
    

    }

    // Resolving qname when called
    // calling parameter: globalPointer
    private static String resolveQNAME(int pointer, String responseStr){

        String qname = "";
        // Get the two bits for number of letter
        // Convert the numerStr to int
        String tempStr = responseStr.substring(pointer, pointer+2);
        int temp = Integer.parseInt(tempStr, 16);
        // Compressed pointer
        if(tempStr.equals("C0")){
            String compressedMessage = compressedReferece(pointer, responseStr, qname);
            qname = compressedMessage;
            pointer+=4;
        } else {
            // Name first then compressed Message
            // Ends with 00
            for(int i=0; i < temp; i++){
                pointer+=2;
                tempStr = responseStr.substring(pointer, pointer+2);
                String letter = ByteHelper.hexToAscii(tempStr);
                qname+=letter;
            }
            qname+=".";
            pointer+=2;
            // tempStr = responseStr.substring(pointer, pointer+2);
            // temp = Integer.parseInt(tempStr, 16)*2;
            // String compressedMessage = compressedReferece(pointer, responseStr, qname);
            // qname += compressedMessage;
            // pointer+=4;
        }      

        globalPointer=pointer;
        qname = qname.substring(0, qname.length() - 1);
        return qname;
    }


    // Resolving qname when called
    private static String resolveTYPE(int pointer, String response){
        String recordType = "";
        String typeStr = response.substring(pointer, pointer+4);
        int typeInt = Integer.parseInt(typeStr, 16);
        recordType += typeInt;

        globalPointer+=TYPE_OFFSET;
        return recordType;
    }

    // Resolving class when called
    private static String resolveCLASS(int pointer, String response){
        String recordClass = "";
        String classStr = response.substring(pointer, pointer+4);
        int classInt = Integer.parseInt(classStr, 16);
        recordClass += classInt;

        globalPointer+=CLASS_OFFSET;
        return recordClass;
    }

    // Resolving TTL when called
    private static String resolveTTL(int pointer, String response){
        String TTL = "";
        String TTLStr = response.substring(pointer, pointer+8);
        int TTLInt = Integer.parseInt(TTLStr, 16);
        TTL += TTLInt;

        globalPointer+=TTL_OFFSET;
        return TTL;
    }

    // Resolving Rdata when called
    private static String resolveRDATA(int pointer, String response, String recordtype){
        String Rdata = "";
        // Get RLength of the whole Rdata message (4 bits)
        String rDataLengthStr = response.substring(pointer, pointer+4);
        int rDataLength = Integer.parseInt(rDataLengthStr, 16);
        pointer+=RLENGTH_OFFSET;
        if(recordtype.equals("2") || recordtype.equals("5")){
                // Start read (pointer, pointer+2)
                // READ hexToAscii
                // pointer increases by 2
                // Add "." when done
                for(int i=0; i < rDataLength; i++){
                    String letterCountStr = response.substring(pointer, pointer+2);
                    int letterCount = Integer.parseInt(letterCountStr, 16);
                    if(letterCountStr.equals("C0")){
                        String compressedMessage = compressedReferece(pointer, response, Rdata);
                        Rdata = compressedMessage;
                        Rdata += "."; 
                        i++;
                        pointer+=4;
                    } else {
                        for(int j=0; j < letterCount; j++){
                            pointer+=READING_OFFSET;
                            String tempStr = response.substring(pointer, pointer+2);
                            String temp = ByteHelper.hexToAscii(tempStr);
                            i++;
                            Rdata += temp;                       
                        }
                        Rdata += ".";                      
                        pointer+=READING_OFFSET;
                    }         
                }
                Rdata = Rdata.substring(0, Rdata.length() - 1); 
        } else if(recordtype.equals("1")){
                // CLASS A (1)
                // Start read (pointer, pointer+2)
                // READ parseInt
                // pointer increases by 2
                // Add "." when done
                for(int i=0; i < rDataLength; i++){
                    String tempStr = response.substring(pointer, pointer+2);
                    int temp = Integer.parseInt(tempStr, 16);
                    pointer+=READING_OFFSET;
                    Rdata += (temp + ".");
                }
        } else if(recordtype.equals("28")){
                // CLASS AAAA (28)
                // RLength is cut in half because IPv6 is read every four bits
                // Start read (pointer, pointer+4)                 
                // remove leading zeros
                // String number = datatempStr.replaceFirst("^0+(?!$)", "");
                // make sure 0 is kept 
                // pointer increases by 4
                // Add ":" when done
                // Rdata += number + ":";
                for(int i=0; i < rDataLength/2; i++){
                    String tempStr = response.substring(pointer, pointer+4);
                    String temp = tempStr.replaceFirst("^0+(?!$)", "");
                    pointer+=4;
                    Rdata += temp + ":";
                }
        }        
        globalPointer=pointer;
        if(Rdata.length() > 0){
            Rdata = Rdata.substring(0, Rdata.length() - 1);   
        }
            
        return Rdata;
    }





    public static String getQNAME(HashMap<String, String> lst){
        String ans = lst.get("qname");
        return ans;
    }

    public static String getType(HashMap<String, String> lst){
        String ans = lst.get("type");
        return ans;
    }

    public static String getTTL(HashMap<String, String> lst){
        String ans = lst.get("TTL");
        return ans;
    }

    public static String getRdata(HashMap<String, String> lst){
        String ans = lst.get("Rdata");
        return ans;
    }

    public static void clearList(){
        A_info.clear();
        AAAA_info.clear();
        CNAME_info.clear();
        NS_info.clear();
        MX_info.clear();
        SOA_info.clear();
        OTHER_info.clear();
        answerRecord.clear();
        nameServerRecord.clear();
        additionalRecord.clear();
        authoritativeAnswers.clear();
    }
}