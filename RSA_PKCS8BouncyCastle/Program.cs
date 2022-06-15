// See https://aka.ms/new-console-template for more information
using RSA_PKCS8BouncyCastle;
using System.Text;

Console.WriteLine("Hello, World!");


string privateKeyPem = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCTqFH65mTZLGmm5fWVbgSisLlYpIzWjmOu9lOG9ltH6Ia/Mn5Fnh2iRiYRGs8AzAoNgrOfWy6enK/5lvZa0VWxdw9Hq+mE11pEjh+vo3igvxsHw1Wp2f5cqhMgVT96V2WrSlha6IiQwvFQl72kQXx8sYsTk985OUX78VoUeD8OVXgU0bOXL2JrHfSRNzcQYV1QTrN67Mj6B3QIa4oLUGbB2wxW5jGtxAEOq+WrIyv9Y5IX7oqbHIDMc9L+VG89HnlEVot/Hca+6O1PoDGHygjFIyRXfwZzhaZz8BbAUJCQcWHg0CCY8S4Bj0gWnGiF+U0mezaHukyCZoiM3o3j7RZ5AgMBAAECggEAd82cJoyEysiEOIxghAut6yqkV827D+Kb8rud7eU5DtEVc1BOr8GonZ95B2vPBQCIL4oan3NmEf9jsIjR/cHXW5QUa7yKTeRFM1Z1Uxa5qwMjtVrByHw9K4Y62oMQa/05Wo+JvMjq9TmWfiOAFSOlE68h/pJ+DXnw1Ihw5CbkUoW+lfJkst1ZFSELatX8RMXLccuu06SzGKrnJYtGX3WtTXhs4ShCGuHqowQNzR8UyNPL5tJ1UQTeX8yi6NKkptcnb3IxPOCKDuogF97W/yEXeSxuC2UJfXEvc8fvEQ/D0MuhhWokK8oYoKJ0iMWkf7TeGJaWHB9+XcCJnlks7PXOmQKBgQDKYG1DT840M85qMQmEI+LzGZ348wbrF/JThLHqe66Wsyb+qlnrqRLADRY0u0BMQrQDLq/h2m/3YQ1rTkkHLVfjyi+SGb98JxqEIP1LZ9bzlY4lgfmhjjiGwspC4DFUg+QhyqUEEgziDlP74H4Io/dW1PVm45Hy9NcatDhPoXnPwwKBgQC6yDGpukUTDQ8fF7Ivd96xHzDTpVrGkLgucfosyFrazDBquAKkuyNd41PsOa+8a8Z2KYZQ2DI3Q4DQNeVsbQp3Ik+Q13hj9THfBN8zIE4td+T+uChit6D3fzJZv8F3Jc+IglbvFs/JEBL+5WjT4jtv7rCUJrw3Z0MnLS+mMRr5EwKBgHLg/eUh3jm/1sJtB6vc+y1oM0ZoHltBgqtqPdyPTPH6zH3vkY+2sBAY3awdR0iC7NCJpgmdB8Xzb7yj+cx7LtL9qLdUql/9io3KdD5juZ8YHFKqT1wn8Wp+FHaV8Sq6m7ua3sVKwclovL/UFXcuLG87//nh4K170scz2mtJjG4lAoGAeGS/9joVegEp5Q2+EfC+/wYuz80+pMz1myJmcmU2gt+oubEgKxRg6Iy2NIa+asJBazq60/N28r41EoAbAHeMjlv0U1U/yZZrbehTAj5phc9JMJJ9nZvlSoKXbtg2GNmrWr9Az92xU1VkGR7AIgsp6q087lHFciTCWUc79nCihTcCgYEAlzFctq2NosJduAivpeJZGR7i0mR1ciypJiKDllrkuvP5qKMYb6vKAGgvnMm9a5rdj32ejYtVZRZhU9pd50U9np/YbILu1sR/wXOzm4NCq7L4JDW/vJV+kMpkJu/mIRo00zp84+JGGjDCA3wvlQ/iVpa4hxPNjjlKfIlPLEIbMX8=";
string publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk6hR+uZk2SxppuX1lW4EorC5WKSM1o5jrvZThvZbR+iGvzJ+RZ4dokYmERrPAMwKDYKzn1sunpyv+Zb2WtFVsXcPR6vphNdaRI4fr6N4oL8bB8NVqdn+XKoTIFU/eldlq0pYWuiIkMLxUJe9pEF8fLGLE5PfOTlF+/FaFHg/DlV4FNGzly9iax30kTc3EGFdUE6zeuzI+gd0CGuKC1BmwdsMVuYxrcQBDqvlqyMr/WOSF+6KmxyAzHPS/lRvPR55RFaLfx3GvujtT6Axh8oIxSMkV38Gc4Wmc/AWwFCQkHFh4NAgmPEuAY9IFpxohflNJns2h7pMgmaIjN6N4+0WeQIDAQAB";
string signType = "RSA2";



Dictionary<string, string> ParamInfo = new Dictionary<string, string>();
ParamInfo.Add("timestamp", "20191112135000");
ParamInfo.Add("noncestr", "123sdsf");
ParamInfo.Add("name", "张三");

//对报文中出现签名域（signature）之外的所有数据元按照key的ascii顺序排序，然后以&作为连接符拼接成待签名串。
string signContent = GetSignContent(ParamInfo);


string signatureNew = string.Empty;
string SignerSymbol = string.Empty;
if (signType == "RSA")
{
    SignerSymbol = "SHA1WithRSA";
}
else
{
    SignerSymbol = "SHA256WithRSA";
}
SignHelper helper = new SignHelper();
helper.RSASigning(Encoding.UTF8, SignerSymbol);
signatureNew = helper.Sign(signContent, privateKeyPem);


bool check = false;
check = helper.Verify(signContent, signatureNew, publicKey);


Console.WriteLine(check);

Console.ReadLine();

/// <summary>
/// 待签字符串
/// </summary>
/// <param name="parameters"></param>
/// <returns></returns>
static string GetSignContent(IDictionary<string, string> parameters)
{
    // 第一步：把字典按Key的字母顺序排序
    IDictionary<string, string> sortedParams = new SortedDictionary<string, string>(parameters);
    IEnumerator<KeyValuePair<string, string>> dem = sortedParams.GetEnumerator();

    // 第二步：把所有参数名和参数值串在一起
    StringBuilder query = new StringBuilder("");
    while (dem.MoveNext())
    {
        string key = dem.Current.Key;
        string value = dem.Current.Value;
        if (!string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(value))
        {
            query.Append(key).Append("=").Append(value).Append("&");
        }
    }
    string content = query.ToString().Substring(0, query.Length - 1);

    return content;
}



