using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PaddingOracleExample.Application
{
    public partial class Default : System.Web.UI.Page
    {
        private readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        private readonly Dictionary<string, HashSet<string>> _entitiesGroups = new Dictionary<string, HashSet<string>>
        {
            {"animal", new HashSet<string> {"cat", "dog", "guinea pig"}},
            {"plant", new HashSet<string> {"cactus", "rose", "thistle"}},
            {"thing", new HashSet<string> {"table", "spoon", "car"}},
        };

        protected void Page_Load(object sender, EventArgs e)
        {
            if (Request.HttpMethod == "GET")
            {
                string answer;
                Question.Text = GenerateQuestion(out answer);
                Answer.Visible = true;
                Question.Visible = true;
                Result.Visible = false;
                SendButton.Visible = true;
                EncryptedAnswer.Value = Convert.ToBase64String(Encrypt(answer));
            }
            else
            {
                var rightAnswer = Decrypt(Convert.FromBase64String(EncryptedAnswer.Value));
                if (!String.Equals(rightAnswer, Answer.Text, StringComparison.CurrentCultureIgnoreCase))
                {
                    Result.ForeColor = Color.Red;
                    Result.Text = string.Format("Wrong answer! Right answer was: {0}", rightAnswer);
                }
                else
                {
                    Result.ForeColor = Color.Green;
                    Result.Text = "Right answer!";
                }
                Answer.Visible = false;
                Question.Visible = false;
                Result.Visible = true;
                SendButton.Visible = false;
            }
        }

        private string GenerateQuestion(out string answer)
        {
            var getRandomGroupKey =
                new Func<string>(() => _entitiesGroups.ElementAt(GetRandom(_entitiesGroups.Keys.Count)).Key);

            var answerGroupKey = getRandomGroupKey();
            answer = _entitiesGroups[answerGroupKey].ElementAt(GetRandom(_entitiesGroups[answerGroupKey].Count));

            string nonAnswerGroupKey;
            do
            {
                nonAnswerGroupKey = getRandomGroupKey();
            } while (nonAnswerGroupKey == answerGroupKey);

            var allEntities = new List<string>(_entitiesGroups[nonAnswerGroupKey]) {answer};

            return string.Format("Select {0} from: {1}", answerGroupKey,
                string.Join(", ", allEntities.OrderBy(a => Guid.NewGuid())));
        }

        private int GetRandom(int maxValue, int minValue = 0)
        {
            var randomByte = new byte[1];
            _rng.GetBytes(randomByte);
            return randomByte[0] % maxValue + minValue;
        }

        private static byte[] Encrypt(string plainText)
        {
            var plainBytes = Encoding.ASCII.GetBytes(plainText);

            using (var encryptor = GetEncryptor())
            {
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(plainBytes, 0, plainBytes.Length);
                        cs.Close();
                    }
                    return ms.ToArray();
                }
            }
        }

        private static string Decrypt(byte[] encryptedBytes)
        {
            using (var encryptor = GetEncryptor())
            {
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedBytes, 0, encryptedBytes.Length);
                        cs.Close();
                    }
                    return Encoding.ASCII.GetString(ms.ToArray());
                }
            }
        }

        private static SymmetricAlgorithm GetEncryptor()
        {
            var encryptor = Aes.Create();
            Debug.Assert(encryptor != null, "encryptor != null");

            encryptor.BlockSize = 128;
            encryptor.Key = Encoding.ASCII.GetBytes("n73rna1$3(r37k3y");
            encryptor.IV = new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
            encryptor.Mode = CipherMode.CBC;
            encryptor.Padding = PaddingMode.PKCS7;

            return encryptor;
        }

        protected override void SavePageStateToPersistenceMedium(object state) { }

        protected override object LoadPageStateFromPersistenceMedium()
        {
            return null;
        }

        protected override object SaveViewState()
        {
            return null;
        }
    }
}