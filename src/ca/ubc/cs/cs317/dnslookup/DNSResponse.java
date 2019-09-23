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
        globalPointer+=ANCOUNT_OFFSET;

        // Number of name servers
        
        String numNameServerStr = message.substring(globalPointer, globalPointer+4);
        numNameServer = Integer.parseInt(numNameServerStr, 16);
        recordAmount[1] = numNameServer;
        globalPointer+=NSCOUNT_OFFSET;

        // Number of additional records
        
        String numAdditionalRecordStr = message.substring(globalPointer, globalPointer+4);
        numAdditionalRecord = Integer.parseInt(numAdditionalRecordStr, 16);
        recordAmount[2] = numAdditionalRecord;
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

        if(termamountStr.equals("C1")){
            pointer+=1;
            String pointStr = message.substring(pointer, pointer+3);
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
                if(is_AA && DNSQuery.qtype.equals("0001") && recordType.equals("1")){
                    authoritativeAnswers.add(decordedRecord);
                } else if(is_AA && DNSQuery.qtype.equals("0005") && recordType.equals("5")){
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
        switch(recordType){
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
        System.out.println("At resolveQNAME: " + pointer);
        String qname = "";
        // Get the two bits for number of letter
        // Convert the numerStr to int
        String tempStr = responseStr.substring(pointer, pointer+2);
        int temp = Integer.parseInt(tempStr, 16);
        // Compressed pointer
        if(tempStr.equals("C0") || tempStr.equals("C1")){
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

            // C0 after
            tempStr = responseStr.substring(pointer, pointer+2);
            if(tempStr.equals("C0") || tempStr.equals("C1")){
                String compressedMessage = compressedReferece(pointer, responseStr, qname);
                qname += compressedMessage;
                pointer+=4;
            }
        }      
        
        globalPointer=pointer;
        qname = qname.substring(0, qname.length() - 1);
        System.out.println("At resolveQNAME: " + qname);
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
                    if(letterCountStr.equals("C0") || letterCountStr.equals("C1")){
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
                // String temp = response.substring(pointer, pointer+2);
                // System.out.println(temp);
                // if(temp.equals("00")){
                //     System.out.println("Susddhauwhdiuahwduia");
                //     pointer+=READING_OFFSET;
                // }

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