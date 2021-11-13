using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using WebApi.Services;

namespace WebApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class DocumentController : ControllerBase
    {
        private IDocumentService _documents;

        public DocumentController(IDocumentService docs)
        {
            _documents = docs;
        }

        [HttpGet]
        public IActionResult Index()
        {
            var jwtToken = Request.Headers["Authorization"];
            var tokenHandler = new JwtSecurityTokenHandler();
            jwtToken = jwtToken.ToString().Replace("Bearer ", "");
            var jwt = tokenHandler.ReadJwtToken(jwtToken);
            
            var f = jwt.Claims.Where(x => x.Type.Equals("UserId")).Select(x => x.Value).ToArray()[0];

            var documents = _documents.GetAll(Int32.Parse(f));
            return Ok(documents);
        }
    }
}
