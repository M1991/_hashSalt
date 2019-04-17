 public class ClassValidate
    {
      //  decimal decHeatedLength = 0;
      //  decimal decUnHeatedLength = 0;

        public ClassValidate()
        {
            InitializeCulture();
        }

        public void InitializeCulture()
        {
            //string culture;
           // CultureInfo ci = Thread.CurrentThread.CurrentCulture;

            CultureInfo ci = new System.Globalization.CultureInfo("en-IN");
            System.Threading.Thread.CurrentThread.CurrentCulture = ci;
            System.Threading.Thread.CurrentThread.CurrentUICulture = ci;
            ci.NumberFormat.CurrencySymbol = "&#8377;";
        }

        public string GetHash(string text, string passwordFormat="SHA256")
        {
            HashAlgorithm _algorithm;
            switch(passwordFormat.ToUpper())
            {
                case "MD5" : _algorithm = MD5.Create();
                    break;
                case "SHA1": _algorithm = SHA1.Create();
                    break;
                case "SHA256": _algorithm = SHA256.Create();
                    break;
                case "SHA512": _algorithm = SHA512.Create();
                    break;
                default : throw new ArgumentException("Invalid Password Format", "Password Format");
                //  BECAUSE MODEL INHERITS FROM CONTROLLER, MODEL eRROR NOT VALID
                //default: System.Web.WebPages.Html.ModelState.AddModelError(string.Empty, "Invalid username or password");
            }
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            byte[] hash = _algorithm.ComputeHash(bytes);
            string hashString = string.Empty;
            foreach (byte x in hash)
            {
                hashString += String.Format("{0:x2}", x);
            }
            return hashString;
        }


    }
