using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebApi.Entities;
using WebApi.Helpers;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using WebApi.Services;
using WebApi.Models;
using Microsoft.AspNetCore.Http;
using System;

namespace WebApi.Services
{
    public interface IDocumentService
    {
        List<Document> GetAll(int userId);
        Document GetById(int id);
    }

    public class DocumentService : IDocumentService
    {
        private DataContext _context;

        public DocumentService(DataContext dataContext)
        {
            _context = dataContext;
        }

        public List<Document> GetAll(int userId)
        {
            return _context.Documents.Where(x=>x.UserId == userId).Select(x => x).ToList();
        }

        public Document GetById(int id)
        {
            return _context.Documents.Find(id);
        }
    }
}
