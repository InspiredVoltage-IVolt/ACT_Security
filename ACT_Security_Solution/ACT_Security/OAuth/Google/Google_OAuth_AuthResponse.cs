﻿using System;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;
using System.Net;
using System.IO;
using FastExcel;

namespace ACT.Core.Security.OAuth.Google
{
   /// <summary>
   /// Google_OAuth_AuthResponse
   ///   Google_OAuth_AuthResponse is a class that contains all the methods we need to authenticate.You should copy it now the rest of the tutorial will be using methods directly from it.
   /// </summary>
   public class Google_OAuth_AuthResponse
   {
      private string access_token;
      public string Access_token
      {
         get
         {               
            if (DateTime.Now.Subtract(created).Minutes> 30) { refresh(); }
            return access_token;
         }
         set { access_token = value; }
      }
      public string refresh_token { get; set; }
      public string clientId { get; set; }
      public string secret { get; set; }
      public string expires_in { get; set; }
      public DateTime created { get; set; }


      /// Parse the json response 
      /// //  "{\n  \"access_token\" : \"ya29.kwFUj-la2lATSkrqFlJXBqQjCIZiTg51GYpKt8Me8AJO5JWf0Sx6-0ZWmTpxJjrBrxNS_JzVw969LA\",\n  \"token_type\" : \"Bearer\",\n  \"expires_in\" : 3600,\n  \"refresh_token\" : \"1/ejoPJIyBAhPHRXQ7pHLxJX2VfDBRz29hqS_i5DuC1cQ\"\n}"


      public static Google_OAuth_AuthResponse get(string response)
      {
         Google_OAuth_AuthResponse result = (Google_OAuth_AuthResponse)JsonConvert.DeserializeObject(response);
         result.created = DateTime.Now;  
         return result;
      }


      public async void refresh()
      {
         string postData = string.Format("client_id={0}&client_secret={1}&refresh_token={2}&grant_type=refresh_token", this.clientId, this.secret, this.refresh_token);

         HttpClient client = new HttpClient();
         HttpContent content = new ACT_HttpContent(postData);

         var _BaseAddress = new Uri("https://accounts.google.com/o/oauth2/token");

         //var request = (HttpWebRequest)WebRequest.Create("https://accounts.google.com/o/oauth2/token");
         //var data = Encoding.ASCII.GetBytes(postData);

         //request.Method = "POST";
         //request.ContentType = "application/x-www-form-urlencoded";
         //request.ContentLength = data.Length;

         var stream = await client.PostAsync(_BaseAddress, content);
                                                 
       //  stream.
            //stream.Write(data, 0, data.Length);
         

         //var response = (HttpWebResponse)request.GetResponse();
         //var responseString = new StreamReader(response.GetResponseStream()).ReadToEnd();
         //var refreshResponse = Google_OAuth_AuthResponse.get(responseString);
         //this.access_token = refreshResponse.access_token;
         //this.created = DateTime.Now;
      }


      public static Google_OAuth_AuthResponse Exchange(string authCode, string clientid, string secret, string redirectURI)
      {

         var request = (HttpWebRequest)WebRequest.Create("https://accounts.google.com/o/oauth2/token");

         string postData = string.Format("code={0}&client_id={1}&client_secret={2}&redirect_uri={3}&grant_type=authorization_code", authCode, clientid, secret, redirectURI);
         var data = Encoding.ASCII.GetBytes(postData);

         request.Method = "POST";
         request.ContentType = "application/x-www-form-urlencoded";
         request.ContentLength = data.Length;

         using (var stream = request.GetRequestStream())
         {
            stream.Write(data, 0, data.Length);
         }

         var response = (HttpWebResponse)request.GetResponse();

         var responseString = new StreamReader(response.GetResponseStream()).ReadToEnd();

         var x = Google_OAuth_AuthResponse.get(responseString);

         x.clientId = clientid;
         x.secret = secret;

         return x;

      }



      public static Uri GetAutenticationURI(string clientId, string redirectUri)
      {
         string scopes = "https://www.googleapis.com/auth/plus.login email";

         if (string.IsNullOrEmpty(redirectUri))
         {
            redirectUri = "urn:ietf:wg:oauth:2.0:oob";
         }
         string oauth = string.Format("https://accounts.google.com/o/oauth2/auth?client_id={0}&redirect_uri={1}&scope={2}&response_type=code", clientId, redirectUri, scopes);
         return new Uri(oauth);
      }

   }
}
