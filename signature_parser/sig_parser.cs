using System.IO;

namespace tether_signature_parser{
    public static class TetherSignatureParser{
        public static void VisualizeSignatures(List<TetherSignature> signatures){
            foreach(TetherSignature i in signatures){
                if(i.type == TetherSignature.TetherSignatureClassification.simple){
                    Console.WriteLine(string.Format("[SIMPLE] -- {0} ({1})", i.name, i.GetImmediateLengthBytes()));
                }
                else if(i.type == TetherSignature.TetherSignatureClassification.complex){
                    if(i.members != null){
                        Console.WriteLine(string.Format("[COMPLEX] -- {0}", i.name));
                        foreach(var k in i.members){
                            Console.WriteLine(string.Format("> +{2}: {0} ({1})", k.Item1, k.Item2, k.Item3));
                        }
                    }
                }
            }
        }
        
        public static List<TetherSignature> LoadSignatureFile(string filename){
            List<TetherSignature> signatureList = new List<TetherSignature>();

            byte[] fileBytes = System.IO.File.ReadAllBytes(filename);

            int j = fileBytes.Length; // 'j' just holds where the cursor stops reading the file, for the next section to start

            /// Iterate over every byte, parsing it into 'simple' tether signatures until a free '0x0A' character is found, 
            /// indicating the beginning of the next section
            string signatureName = "";

            for(int i = 0; i < fileBytes.Length; i++){
                byte currentByte = fileBytes[i];
                
                if(currentByte == ':'){
                    if(i<fileBytes.Length-1){
                        uint sigLen = fileBytes[i+1];
                        signatureList.Add(new TetherSignature(signatureName, TetherSignature.TetherSignatureClassification.simple, sigLen));
                        signatureName = "";
                        i = i + 1;
                    }
                    else{
                        throw new Exception("A signature was found where the length definition would be beyond the end of the file!");
                    }
                }
                else if(currentByte == 10){
                    j = i + 1;
                    break;
                }
                else{
                    signatureName += ((char)currentByte);
                }
            }

            /// Parse complex signatures
            for(int i = j; i < fileBytes.Length; i++){
                byte currentByte = fileBytes[i];
                if(currentByte == ':'){
                    /// Search backwards from the ':' character, collecting characters for the signature's name
                    /// until we reach an 0x0A (newline), 0x21 ('!'), or the beginning of the file    
                    string complexSigName = "";
                    for(int l = i-1; i >= 0; l--){
                        var lbyte = fileBytes[l];
                        if(!(Char.IsLetterOrDigit((char)lbyte) || lbyte == '_')){
                            break;
                        }
                        complexSigName = complexSigName.Insert(0, ((char)lbyte).ToString());
                    }

                    /// Search forwards from the ':' character, collecting bytes for the signature's body
                    /// until we reach an 0x0A (newline), 0x21 ('!'), or EOF
                    
                    List<byte> sigBody = new List<byte>();
                    for(int l = i+1; i < fileBytes.Length; l++){
                        var lbyte = fileBytes[l];
                        if(lbyte == '!' || lbyte == 10){
                            break;
                        }
                        sigBody.Add(lbyte);
                    }

                    /// Search forwards from the body, until the '#' symbol is reached.
                    /// Afterwards grab the next four bytes, storing them as the offset.
                    /// Then, starting from after that march forward until a '|' character
                    /// or the end of the body is found, storing those characters as the name

                    string memberTypeName = ""; 
                    List<Tuple<string, string, int>> members = new List<Tuple<string, string,int>>();
                    for(int l = 0; l < sigBody.Count; l++){
                        var lbyte = sigBody[l];
                        if(lbyte=='#'){
                            int offset = (sigBody[l+1] << 24) | (sigBody[l+2] << 16) | (sigBody[l+3] << 8) | sigBody[l+4];
                            
                            string memberName = "";
                            for(l+=5;l < sigBody.Count; l++){
                                if(sigBody[l] == '|'){
                                    break;
                                }
                                memberName += ((char)sigBody[l]).ToString();
                            }

                            members.Add(new Tuple<string, string,int>(memberTypeName, memberName, offset));
                            memberTypeName = "";
                            continue;
                        }

                        memberTypeName += ((char)lbyte).ToString();
                    }

                    var s = new TetherSignature(complexSigName, TetherSignature.TetherSignatureClassification.complex, 4);
                    s.members = members;
                    signatureList.Add(s);
                }
            }

            return signatureList;
        }

        public static List<byte[]> SplitBytes(byte[] bytes, byte separator){
            List<byte[]> result = new List<byte[]>();

            List<byte> b = new List<byte>();
            for(int j = 0; j < bytes.Length; j++){
                b.Add(bytes[j]);
            }
            for(int i = 0; i < bytes.Length; i++){
                if(bytes[i] == separator){
                    List<byte> a = new List<byte>();
                    b = new List<byte>();
                    for(int j = 0; j < i; j++){
                        a.Add(bytes[j]);
                    }
                    for(int j = i + 1; j < bytes.Length; j++){
                        b.Add(bytes[j]);
                    }
                    result.Add(a.ToArray());
                    bytes = b.ToArray();
                    i = 0;
                }
            }
            result.Add(b.ToArray());

            return result;
        }
    }

    public class TetherSignature{
        /// <summary>
        /// A data signature can be represented by one of three types in tether:
        /// 
        /// > A 'fundamental,' this data type contains exactly one value and can be easily modified
        /// by binary and unary operators without a member specifier. A fundamental is gauranteed to
        /// occupy 8 bytes or less, ensuring it can easily be operated upon simply in the general
        /// purpose registers.
        /// 
        /// > A 'simple.' Much like a fundamental, a simple must occupy 8 bytes or less, but a simple
        /// may have one or more child values, or 'members,' who may be referred to by name by 
        /// the programmer. A good example of a simple is an int vector, which will contain a pair
        /// of integer (dword) values who may be accessed individually with the '.' operator but moved by one, totalling
        /// up to a single quad word
        /// 
        /// > A 'complex.' Like a simple a complex data signature may contain one or more child members, though
        /// they will be accessed by the '->' operator (unless the '.' operator ends up universally recognized
        /// by the compiler.) Unlike a simple, however, a complex will not be stored directly in registers,
        /// instead existing in memory. The immediate value (present in registers) of a complex is the 8 byte
        /// pointer to the data's location in memory.
        /// </summary>
        public enum TetherSignatureClassification{
            fundamental,
            simple,
            complex
        }
        public readonly TetherSignatureClassification type;

        public List<Tuple<string, string, int>>? members;

        public readonly string name = "";
        
        private uint _immediateLengthBytes = 0;

        public TetherSignature(string name, TetherSignatureClassification type, uint immediateLengthBytes = 0){
            this.name = name;
            this.type = type;
            this._immediateLengthBytes = immediateLengthBytes;
        }

        public uint GetImmediateLengthBytes(){
            if(type==TetherSignatureClassification.complex){
                return 8;
            }
            return _immediateLengthBytes;
        }
    }
}