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
    private static int hexStr_bytePointer = 0;
    public static int numAnswer;
    public static int numNameServer;
    public static int numAdditionalRecord;

    // OFFSETS
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
        System.out.println("-------------------Check point 5------------------------");
        hexStr_bytePointer = 0;
        
        hexStr_bytePointer+=ID_OFFSET;

        // aa is at index 5 in the 16 bits
        is_AA = is_authoritative(hexStr_bytePointer, message);
        hexStr_bytePointer+=QR_OFFSET;

        System.out.println("-------------------Check point 6------------------------");
        // Number of questions
        hexStr_bytePointer+=QDCOUNT_OFFSET;

        // Number of answers
        
        String numAnswerStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
        numAnswer = Integer.parseInt(numAnswerStr, 16);
        System.out.println("numAnswer: "+ numAnswer);
        hexStr_bytePointer+=ANCOUNT_OFFSET;
        System.out.println("-------------------Check point 7------------------------");

        // Number of name servers
        
        String numNameServerStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
        numNameServer = Integer.parseInt(numNameServerStr, 16);
        hexStr_bytePointer+=NSCOUNT_OFFSET;
        System.out.println("numNameServer: "+ numNameServer);
        System.out.println("-------------------Check point 8------------------------");

        // Number of additional records
        
        String numAdditionalRecordStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
        numAdditionalRecord = Integer.parseInt(numAdditionalRecordStr, 16);
        System.out.println("numAdditionalRecord: "+ numAdditionalRecord);
        hexStr_bytePointer+=ARCOUNT_OFFSET;
        System.out.println("-------------------Check point 9------------------------");

        String pointerStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
        while(!pointerStr.equals("00")){
            hexStr_bytePointer+=READING_OFFSET;
            pointerStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
        }
        // Shifting byte after getting "00"
        hexStr_bytePointer+=READING_OFFSET;
        System.out.println("-------------------Check point 10------------------------");

        hexStr_bytePointer+=QTYPE_OFFSET;

        hexStr_bytePointer+=QCLASS_OFFSET;

        for(int a=0; a< numAnswer; a++){
            System.out.println("-------------------Check point a------------------------");
            HashMap<String, String> answerInfo = new HashMap<String, String>();
            // Common things of the two
            // Name server
            
            hexStr_bytePointer+=2;
            String qname = "";
            String qnamepointerStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
            int qnamepointer = Integer.parseInt(qnamepointerStr, 16)*2;
            qname = pointerString(qnamepointer, message, qname);
            qname = qname.substring(0, qname.length() - 1);
            answerInfo.put("qname", qname);
            hexStr_bytePointer+=READING_OFFSET;
            System.out.println("-------------------Check point b------------------------");
            // Type
            String typeStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int typeInt = Integer.parseInt(typeStr, 16);
            String recordType = Integer.toString(typeInt);
            answerInfo.put("type", recordType);
            hexStr_bytePointer += TYPE_OFFSET;
            System.out.println("-------------------Check point c------------------------");
            // Class
            String classStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int classInt = Integer.parseInt(classStr, 16);
            answerInfo.put("class", Integer.toString(classInt));
            hexStr_bytePointer += CLASS_OFFSET;
            System.out.println("-------------------Check point d------------------------");

            // TTL
            String TTLStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+8);
            int TTLInt = Integer.parseInt(TTLStr, 16);
            answerInfo.put("TTL", Integer.toString(TTLInt));
            hexStr_bytePointer += TTL_OFFSET;
            System.out.println("-------------------Check point e------------------------");

            // RLength
            String RLengthStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int RLength = Integer.parseInt(RLengthStr, 16);
            hexStr_bytePointer += RLENGTH_OFFSET;
            System.out.println("-------------------Check point f------------------------");

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
                        Rdata = Rdata.substring(0, Rdata.length() - 1);
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
                // Rdata = Rdata.substring(0, Rdata.length() - 1);
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
            }

            System.out.println("-------------------Check point g------------------------");
            // Removing extra "."
            Rdata = Rdata.substring(0, Rdata.length() - 1);
            answerInfo.put("Rdata", Rdata);

            // Put each type in different list
            // Type A
            switch(answerInfo.get("type")){
                // Type A
                case "1":
                    A_info.add(answerInfo);
                    break;
                // Type NS
                case "2":
                    NS_info.add(answerInfo);
                    break;
                // Type CNAME
                case "5":
                    CNAME_info.add(answerInfo);
                    break;
                // TYPE SOA
                case "6":
                    SOA_info.add(answerInfo);
                    break;
                // Type MX
                case "15":
                    MX_info.add(answerInfo);
                    break;
                // Type AAAA
                case "28":
                    AAAA_info.add(answerInfo);
                    break;
                // Type OTHER
                case "0":
                    OTHER_info.add(answerInfo);
                    break;
            }
            answerRecord.add(answerInfo);
            if(is_AA){
                authoritativeAnswers.add(answerInfo);
            }
                       
        }
        System.out.println("-------------------Check point 11------------------------");
        for(int ns=0; ns < numNameServer; ns++){
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
                        hexStr_bytePointer+=READING_OFFSET;
                        String RdatapointerStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
                        int Rdatapointer = Integer.parseInt(RdatapointerStr, 16)*2;  
    
                        Rdata = pointerString(Rdatapointer, message, Rdata);
                        hexStr_bytePointer+=READING_OFFSET;
                        j+=2;
                    } else {
                    // CASE TWO where theres no pointer 
                        for(int k=0; k < datatempInt; k++){
                            hexStr_bytePointer+=READING_OFFSET;
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
            nameServerRecord.add(nameServerInfo);
            
        }
        System.out.println("-------------------Check point 12------------------------");
        for(int aa=0; aa < numAdditionalRecord; aa++){
            System.out.println(aa);
            HashMap<String, String> additionalInfo = new HashMap<String, String>();
            // Common things of the two
            // Name server
            // at 181 OFF SET
            // CHECK IF IT HAS C0 OR NOT
            String qname = "";
            String qnameStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);   
            if(qnameStr.equals("C0") || qnameStr.equals("C1") ){
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
            System.out.println("-------------------Check point a------------------------");
            additionalInfo.put("qname", qname);
            hexStr_bytePointer+=2;

            // Type
            // At 183 OFF SET
            String typeStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int typeInt = Integer.parseInt(typeStr, 16);
            String recordType = Integer.toString(typeInt);
            additionalInfo.put("type", recordType);
            hexStr_bytePointer += 4;
            System.out.println("-------------------Check point b------------------------");
            // Class
            String classStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);   
            int classInt = Integer.parseInt(classStr, 16);
            additionalInfo.put("class", Integer.toString(classInt));
            hexStr_bytePointer += 4;

            System.out.println("-------------------Check point c------------------------");
            // TTL
            String TTLStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+8);
            // TODO ERROR FOUND HERE
            int TTLInt = Integer.parseInt(TTLStr, 16);
            additionalInfo.put("TTL", Integer.toString(TTLInt));
            hexStr_bytePointer += 8;
            System.out.println("-------------------Check point d------------------------");
            // RLength
            String RLengthStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+4);
            int RLength = Integer.parseInt(RLengthStr, 16);
            hexStr_bytePointer += 4;

            System.out.println("-------------------Check point e------------------------");
            // RData TODO 
            // If IPv4 
            String Rdata = "";  
            if(recordType.equals("2") || recordType.equals("5")){
                // IF TYPE NS OR CNAME
                for(int j=0; j < RLength; j++){
                    String datatempStr =  message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
                    int datatempInt = Integer.parseInt(datatempStr, 16);
    
                    // CASE ONE where theres a pointer(compressed message)
                    if(datatempStr.equals("C0")){
                        hexStr_bytePointer+=READING_OFFSET;
                        String RdatapointerStr = message.substring(hexStr_bytePointer, hexStr_bytePointer+2);
                        int Rdatapointer = Integer.parseInt(RdatapointerStr, 16)*2;  
    
                        Rdata = pointerString(Rdatapointer, message, Rdata);
                        hexStr_bytePointer+=READING_OFFSET;
                        Rdata = Rdata.substring(0, Rdata.length() - 1);
                        j+=2;
                    } else {
                    // CASE TWO where theres no pointer 
                        for(int k=0; k < datatempInt; k++){
                            hexStr_bytePointer+=READING_OFFSET;
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
            }
          
            System.out.println("-------------------Check point j------------------------");
            System.out.println(Rdata);
            if(Rdata.length() >= 1){
                System.out.println("In Rdata if");
                Rdata = Rdata.substring(0, Rdata.length() - 1);
            }
            
            System.out.println("below Rdata");
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
            additionalRecord.add(additionalInfo);
            
        }
        System.out.println("-------------------Check point 13------------------------");
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

    private static boolean is_authoritative(int pointer, String response){
        String QRStr = response.substring(hexStr_bytePointer, hexStr_bytePointer+4);
        int QRInt = Integer.parseInt(QRStr, 16);
        String QRBinary = Integer.toBinaryString(QRInt); 
        char is_authoritative = QRBinary.charAt(5);
        if(is_authoritative == '1'){
            return true;
        } else {
            return false;
        }       
    }

    private static String extract_Rdata(int pointer, String response){
        return "";
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

    private static String getNS_CNAME(){
        return "";
    }
    private static String getAAAA(){
        return "";
    }
    private static String getA(){
        return "";
    }
}