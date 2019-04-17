# Hash for passwords


var str = PasswordHashed.ValidatePassword(objCv.GetHash(model.Password, "SHA256").ToUpper(), loginInfo2);

string loginInfo2 = db.users.Where(d => d.username.Equals(model.Username)).Select(m => m.newpassword).First();
