using System;
using System.Text.RegularExpressions;
using tether_signature_parser;

namespace tether_typer
{
    public class Program
    {
        public static int Main(string[] args)
        {
            GenerateSignatures(File.ReadAllText("file.teth"));
            return 0;
        }

        /// <summary>
        /// From the input tether file, 'program,' collect all classes and members, and write it to a machine readable intermediary format
        /// </summary>
        /// <param name="program"></param>
        public static void GenerateSignatures(string program)
        {
            List<string> availableParents = new List<string>();

            /// Use a regex to collect all user defined classes from the program file. Collect all class names and add them to
            /// list of available user defined classes, 'availableParents'. Add all regex matches to a list of regex matches,
            /// and sort them in order of amount of '/' characters in the class name, from low to high. This serves to place
            /// the more fundamental classes before the classes dependent on them, eliminating the possibility of the typer
            /// falsly detecting an orphaned class.

            MatchCollection ms = Regex.Matches(program, EXPR.signatureDef, RegexOptions.Multiline);
            foreach (Match m in ms)
            {
                string e = m.Groups[1].ToString();
                e = Regex.Replace(e, @"\s", "");
                availableParents.Add(e);
            }

            List<Match> sortedSignatureMatches = new List<Match>();
            foreach (Match m in ms)
            {
                sortedSignatureMatches.Add(m);
            }
            sortedSignatureMatches.Sort((Match a, Match b) => { return a.Groups[1].ToString().Count(x => x == '/') - b.Groups[1].ToString().Count(x => x == '/'); });

            /// Iterate over each class body, performing a regex on each. From each regex collect a list of class members.
            /// Finally, iterate over each member and split it into a type and name. Write each member tuple (containing the 
            /// type name and member name. ) to a list where it can later be written to the signature file.
            
            foreach(Match signatureMatch in sortedSignatureMatches){
                string signatureBody = signatureMatch.Groups[2].ToString();
                string signatureName = signatureMatch.Groups[1].ToString();

                MatchCollection memberMatches = Regex.Matches(signatureBody, EXPR.sigDefTargetCapture, RegexOptions.Multiline);
                foreach(Match memberMatch in memberMatches){
                    string memberTypeName = memberMatch.Groups[1].ToString();
                    string memberName = memberMatch.Groups[2].ToString();
                }
            }

            /// Finally parse the member to list to it's binary list. The binary file should occupy a per-byte
            /// format which can easily be understood by a hex editor. The file, separated by newline characters
            /// should contain each signature name, as well as each signatures' members and their corresponding names,
            /// type names, offsets, and lengths (all in bytes)
        }

        public static class EXPR
        {
            public static string signatureDef = @"^\s*signature\s+([A-Za-z0-9/_]+)\s*{([^}]*)}";
            public static string sigDefTargetCapture = @"^\s*([A-Za-z0-9_/]+)\s+([A-Za-z0-9_]+)\s*$";
            public static string inQuotes = @"'.*'";

        }
    }
}