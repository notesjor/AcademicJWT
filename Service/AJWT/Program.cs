using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;


namespace AJWT
{
  public class Program
  {
    private static JsonSerializerOptions _options;
    private static string privateKeyPath = "private.pem";
    private static string publicKeyPath = "public.pem";
    private static RsaSecurityKey _rsa;
    private static string _pem;

    public static void Main(string[] args)
    {
      LoadOrCreateRsaKey();
      var builder = WebApplication.CreateSlimBuilder(args);
      var app = builder.Build();

      _options = new JsonSerializerOptions
      {
        TypeInfoResolver = JsonTypeInfoResolver.Combine(
          new DefaultJsonTypeInfoResolver()
        )
      };

      app.MapGet("/key", () => Results.Text(_pem, "text/plain"));
      app.MapPost("/auth", AuthCall);

      app.Run();
    }

    private static async Task AuthCall(HttpContext context)
    {
      var request = await JsonSerializer.DeserializeAsync<AuthRequest>(context.Request.Body, _options);

      var creds = new SigningCredentials(_rsa, SecurityAlgorithms.RsaSha256);

      var token = new JwtSecurityToken(
        issuer: "JOR-AJWT",
        audience: request.Autdience,
        claims: new[]
        {
          new Claim(JwtRegisteredClaimNames.Sub, request.Email),
          new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        },
        expires: request.Expires,
        signingCredentials: creds
      );
      
      await context.Response.WriteAsync(new JwtSecurityTokenHandler().WriteToken(token));
    }

    public class AuthRequest
    {
      [JsonPropertyName("email")]
      public string Email { get; set; }
      [JsonPropertyName("audience")]
      public string Autdience { get; set; }
      [JsonPropertyName("expires")]
      public DateTime Expires { get; set; }
    }

    private static void LoadOrCreateRsaKey()
    {
      var rsa = RSA.Create();

      if (File.Exists(privateKeyPath))
      {
        rsa.ImportFromPem(File.ReadAllText(privateKeyPath));
      }
      else
      {
        rsa = RSA.Create(4096);

        File.WriteAllText(privateKeyPath, rsa.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(publicKeyPath, rsa.ExportSubjectPublicKeyInfoPem());
      }

      _rsa = new RsaSecurityKey(rsa);
      _pem = rsa.ExportSubjectPublicKeyInfoPem();
    }
  }
}
