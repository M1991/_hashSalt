# Hash for passwords



string loginInfo2 = db.users.Where(d => d.username.Equals(model.Username)).Select(m => m.newpassword).First();
var str = PasswordHashed.ValidatePassword(objCv.GetHash(model.Password, "SHA256").ToUpper(), loginInfo2);


