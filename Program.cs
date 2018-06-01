﻿using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography
{
    class Usuario {
        public Usuario(){} 

        public string nome;
        public string senha;

    }

    public static class SecureString
    {
        public static string GetPassword (){
            string pwd = "";
            while (true)
            {
                ConsoleKeyInfo i = Console.ReadKey(true);
                if (i.Key == ConsoleKey.Enter)
                {
                    break;
                }
                else if (i.Key == ConsoleKey.Backspace)
                {
                    if (pwd.Length > 0)
                    {
                        pwd = pwd.Remove(pwd.Length -1);
                        Console.Write("\b \b");
                    }
                }
                else
                {
                    pwd += i.KeyChar;
                    Console.Write("*");
                }
            }
            return pwd;
        }
    }
    //Classe de cifra de cesar
    class CaesarCypher :IDisposable {

        public string Decrypt (string input){
            string ret = "";
            char n;

            //Itera sobre os chars do input
            foreach(char item in input)
            {
                if(!Char.IsNumber(item))
                    ret += (char)((int) item - 12);
                else
                    ret += item;
            }

            return ret;
        }

        public string Encrypt (string input){
            string ret = "";
            char n;

            //Itera sobre os chars do input
            foreach(char item in input)
            {
                if(!Char.IsNumber(item))
                    ret += (char)((int) item + 12);
                else
                    ret += item;
            }

            return ret;
        }

        public void Dispose (){}
    }

    static class ConsoleMenu{
        public static string RunMenu(){
            Console.Clear();
            Console.WriteLine(" -----------------------------------------");
            Console.WriteLine("|          Select a test to run           |");
            Console.WriteLine("|-----------------------------------------|");
            Console.WriteLine("|     1 - Convert base to MD5.            |");
            Console.WriteLine("|     2 - Convert base to SHA1.           |");
            Console.WriteLine("|     3 - Convert base to SHA256.         |");
            Console.WriteLine("|     4 - Convert base to Salted MD5.     |");
            Console.WriteLine("|     5 - Convert base to Salted SHA1.    |");
            Console.WriteLine("|     6 - Convert base to Salted SHA256.  |");
            Console.WriteLine("|-----------------------------------------|");
            Console.WriteLine("|     7 - Validate MD5 base.              |");
            Console.WriteLine("|     8 - Validate SHA1 base.             |");
            Console.WriteLine("|     9 - Validate SHA256 base.           |");
            Console.WriteLine("|     10 - Validate MD5 Salted base.      |");
            Console.WriteLine("|     11 - Validate SHA1 Salted base.     |");
            Console.WriteLine("|     12 - Validate SHA256 Salted base.   |");
            Console.WriteLine("|-----------------------------------------|");
            Console.WriteLine("|     20 - Show unencrypted base.         |");
            Console.WriteLine("|-----------------------------------------|");
            Console.WriteLine("|     q - Quit program                    |");
            Console.WriteLine(" -----------------------------------------");
            Console.WriteLine("");
            Console.Write("Selection : ");
            string selection = Console.ReadLine();

            return selection;
        }
    }

    class BaseConverter : IDisposable{
        public BaseConverter(){}

        public List<Usuario> ToMD5(List<Usuario> Base, bool Salted){
            List<Usuario> ret = new List<Usuario>();

            MD5 md5Hash = MD5.Create();

            byte[] data;
            // Convert the input string to a byte array and compute the hash.
            
            using(System.IO.StreamWriter writetext = new System.IO.StreamWriter("BaseInMD5.txt"))
            {
                foreach(Usuario item in Base)
                {
                    Usuario temp = new Usuario();

                    temp.nome = item.nome;
                    // Convert the input string to a byte array and compute the hash.
                    if(Salted)
                        data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(item.senha + item.nome));
                    else
                        data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(item.senha));

                    temp.senha = BitConverter.ToString(data).Replace("-", string.Empty);

                    writetext.WriteLine(temp.nome + "|" + temp.senha);

                    ret.Add(temp);
                }
            }
            

            return ret;
        }

        public List<Usuario> ToSHA1(List<Usuario> Base, bool Salted){
            List<Usuario> ret = new List<Usuario>();

            SHA1 sha1hash = SHA1.Create();

            using(System.IO.StreamWriter writetext = new System.IO.StreamWriter("BaseInSHA1.txt"))
            {
                foreach(Usuario item in Base)
                {
                    Usuario temp = new Usuario();

                    temp.nome = item.nome;

                    byte[] data;
                    // Convert the input string to a byte array and compute the hash.
                    if(Salted)
                        data = sha1hash.ComputeHash(Encoding.UTF8.GetBytes(item.senha + item.nome));
                    else
                        data = sha1hash.ComputeHash(Encoding.UTF8.GetBytes(item.senha));

                    temp.senha = BitConverter.ToString(data).Replace("-", string.Empty);

                    writetext.WriteLine(temp.nome + "|" + temp.senha);

                    ret.Add(temp);
                }
            }
            return ret;
        }

        public List<Usuario> ToSHA256(List<Usuario> Base, bool Salted){
            List<Usuario> ret = new List<Usuario>();

            SHA256 sha256hash = SHA256.Create();

            using(System.IO.StreamWriter writetext = new System.IO.StreamWriter("BaseInSHA256.txt"))
            {
                foreach(Usuario item in Base)
                {
                    Usuario temp = new Usuario();

                    temp.nome = item.nome;

                    byte[] data;
                    // Convert the input string to a byte array and compute the hash.
                    if(Salted)
                        data = sha256hash.ComputeHash(Encoding.UTF8.GetBytes(item.senha + item.nome));
                    else
                        data = sha256hash.ComputeHash(Encoding.UTF8.GetBytes(item.senha));

                    temp.senha = BitConverter.ToString(data).Replace("-", string.Empty);

                    writetext.WriteLine(temp.nome + "|" + temp.senha);

                    ret.Add(temp);
                }
            }
            return ret;
        }

        public void Dispose(){}
    }

    class BaseValidator : IDisposable{
        public BaseValidator(){}

        public void ValidateMD5(List<Usuario> Base, Usuario User, bool Salted){
            MD5 md5Hash = MD5.Create();

            var watch = System.Diagnostics.Stopwatch.StartNew();

            byte[] data;
                // Convert the input string to a byte array and compute the hash.
            if(Salted)
                data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(User.senha + User.nome));
            else
                data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(User.senha));
            string senha = BitConverter.ToString(data).Replace("-", string.Empty);

            Usuario base_user = (from bu in Base 
                            where bu.nome == User.nome 
                            select bu).SingleOrDefault();

            watch.Stop();
            if(base_user != null){
                if(senha == base_user.senha)
                {
                    Console.Clear();
                    Console.WriteLine("----------------------------------------------------------------------------------");
                    if(Salted)
                        Console.WriteLine("Validation complete! Elaspsed time to validate salted MD5: " + watch.Elapsed.TotalMilliseconds + " Miliseconds");
                    else
                        Console.WriteLine("Validation complete! Elaspsed time to validate MD5: " + watch.Elapsed.TotalMilliseconds + " Miliseconds");

                    Console.WriteLine("-----------------------------------------------------------------------------------");
                    Console.ReadKey();
                }else
                {
                    Console.Clear();
                    Console.WriteLine("-------------------------------------------------------------------------------------------");
                    Console.WriteLine("Something went wrong, user is not Signed or the Password is incorrect. Please try again.");
                    Console.WriteLine("-------------------------------------------------------------------------------------------");
                    Console.ReadKey();
                }   
            }else{
                    Console.Clear();
                    Console.WriteLine("-------------------------------------------------------------------------------------------");
                    Console.WriteLine("Something went wrong, user is not Signed or the Password is incorrect. Please try again.");
                    Console.WriteLine("-------------------------------------------------------------------------------------------");
                    Console.ReadKey();

            }
        }

        public void ValidateSHA1(List<Usuario> Base, Usuario User, bool Salted){
            SHA1 sha1hash = SHA1.Create();

            var watch = System.Diagnostics.Stopwatch.StartNew();

            byte[] data;
                // Convert the input string to a byte array and compute the hash.
            if(Salted)
                data = sha1hash.ComputeHash(Encoding.UTF8.GetBytes(User.senha + User.nome));
            else
                data = sha1hash.ComputeHash(Encoding.UTF8.GetBytes(User.senha));
            string senha = BitConverter.ToString(data).Replace("-", string.Empty);


            Usuario base_user = (from bu in Base 
                            where bu.nome == User.nome 
                            select bu).SingleOrDefault();

            watch.Stop();
            
            if(base_user != null){
                if(senha == base_user.senha)
                {
                    Console.Clear();
                    Console.WriteLine("-------------------------------------------------------------------------------------------");
                    if(Salted)
                        Console.WriteLine("Validation complete! Elaspsed time to validate salted SHA1: " + watch.Elapsed.TotalMilliseconds + " Miliseconds");
                    else
                        Console.WriteLine("Validation complete! Elaspsed time to validate SHA1: " + watch.Elapsed.TotalMilliseconds + " Miliseconds");

                    Console.WriteLine("-------------------------------------------------------------------------------------------");
                    Console.ReadKey();
                }else
                {
                    Console.Clear();
                    Console.WriteLine("-------------------------------------------------------------------------------------------");
                    Console.WriteLine("Something went wrong, user is not Signed or the Password is incorrect. Please try again.");
                    Console.WriteLine("-------------------------------------------------------------------------------------------");
                    Console.ReadKey();
                }   
            }else{
                    Console.Clear();
                    Console.WriteLine("-------------------------------------------------------------------------------------------");
                    Console.WriteLine("Something went wrong, user is not Signed or the Password is incorrect. Please try again.");
                    Console.WriteLine("-------------------------------------------------------------------------------------------");
                    Console.ReadKey();

            } 
        }

        public void ValidateSHA256(List<Usuario> Base, Usuario User, bool Salted){
            SHA256 sha256hash = SHA256.Create();

            var watch = System.Diagnostics.Stopwatch.StartNew();

            byte[] data;
                // Convert the input string to a byte array and compute the hash.
            if(Salted)
                data = sha256hash.ComputeHash(Encoding.UTF8.GetBytes(User.senha + User.nome));
            else
                data = sha256hash.ComputeHash(Encoding.UTF8.GetBytes(User.senha));

            string senha = BitConverter.ToString(data).Replace("-", string.Empty);


            Usuario base_user = (from bu in Base 
                            where bu.nome == User.nome 
                            select bu).SingleOrDefault();

            watch.Stop();
            
            if(base_user != null){
                if(senha == base_user.senha)
                {
                    Console.Clear();
                    Console.WriteLine("-------------------------------------------------------------------------------------------");
                    if(Salted)
                        Console.WriteLine("Validation complete! Elaspsed time to validate salted SHA256: " + watch.Elapsed.TotalMilliseconds + " Miliseconds");
                    else
                        Console.WriteLine("Validation complete! Elaspsed time to validate SHA256: " + watch.Elapsed.TotalMilliseconds + " Miliseconds");

                    Console.WriteLine("--------------------------------------------------------------------------------------------");
                    Console.ReadKey();
                }else
                {
                    Console.Clear();
                    Console.WriteLine("-------------------------------------------------------------------------------------------");
                    Console.WriteLine("Something went wrong, user is not Signed or the Password is incorrect. Please try again.");
                    Console.WriteLine("-------------------------------------------------------------------------------------------");
                    Console.ReadKey();
                }   
            }else{
                    Console.Clear();
                    Console.WriteLine("-------------------------------------------------------------------------------------------");
                    Console.WriteLine("Something went wrong, user is not Signed or the Password is incorrect. Please try again.");
                    Console.WriteLine("-------------------------------------------------------------------------------------------");
                    Console.ReadKey();

            }
        }

        public void Dispose(){}
    }

    class Program
    {
        static void Main(string[] args)
        {
            //Perguntar ao usuario o caminho do txt
            Console.Write("Please insert the absolute path of the base to be converted: ");
            string filePath = Console.ReadLine();

            //Ler linhas do arquivo .txt que contem as senhas e os usuarios
            string[] lines = System.IO.File.ReadAllLines(filePath);

            //Init lista de usuarios
            List<Usuario> usuarios_as_is = new List<Usuario>();
            List<Usuario> usuarios_decrypt = new List<Usuario>();
            List<Usuario> usuarios_md5 = new List<Usuario>();
            List<Usuario> usuarios_sha1 = new List<Usuario>();
            List<Usuario> usuarios_sha256 = new List<Usuario>();
            List<Usuario> usuarios_md5_salted = new List<Usuario>();
            List<Usuario> usuarios_sha1_salted = new List<Usuario>();
            List<Usuario> usuarios_sha256_salted = new List<Usuario>();
            
            CaesarCypher CaesarC = new CaesarCypher();

            Console.Clear();
            Console.WriteLine("Loading the program, please wait...");

            //Itera sobre as linhas do arquivo para traduzir para uma List
            foreach(string line in lines){
                Usuario temp = new Usuario();
                Usuario asis = new Usuario();

                asis.nome = line.Split("|")[0];
                asis.senha = line.Split("|")[1];

                usuarios_as_is.Add(asis);

                temp.nome = line.Split("|")[0];
                temp.senha = line.Split("|")[1];

                temp.senha = CaesarC.Decrypt(temp.senha);

                usuarios_decrypt.Add(temp);
            }

            using(BaseConverter converter = new BaseConverter())
            {
                usuarios_md5 = converter.ToMD5(usuarios_decrypt, false);
                usuarios_sha1 = converter.ToSHA1(usuarios_decrypt, false);
                usuarios_sha256 = converter.ToSHA256(usuarios_decrypt, false);
                usuarios_md5_salted = converter.ToMD5(usuarios_decrypt, true);
                usuarios_sha1_salted = converter.ToSHA1(usuarios_decrypt, true);
                usuarios_sha256_salted = converter.ToSHA256(usuarios_decrypt, true);
            }

            bool exit = false;
            while(!exit){
                switch(ConsoleMenu.RunMenu()){
                    case "1":
                        using(BaseConverter converter = new BaseConverter())
                        {
                            var watch = System.Diagnostics.Stopwatch.StartNew();
                            usuarios_md5 = converter.ToMD5(usuarios_decrypt, false);
                            watch.Stop();

                            Console.WriteLine("---------------------------------------------------------------------");
                            Console.WriteLine("Elaspsed time to convert base to MD5: " + watch.Elapsed.TotalMilliseconds + " Miliseconds");
                            Console.WriteLine("---------------------------------------------------------------------");
                            Console.ReadKey();
                        }
                    break;
                    case "2":
                        using(BaseConverter converter = new BaseConverter())
                        {
                            var watch = System.Diagnostics.Stopwatch.StartNew();
                            usuarios_sha1 = converter.ToSHA1(usuarios_decrypt, false);
                            watch.Stop();

                            Console.WriteLine("----------------------------------------------------------------");
                            Console.WriteLine("Elaspsed time to convert base to SHA1: " + watch.Elapsed.TotalMilliseconds+ " Miliseconds");
                            Console.WriteLine("----------------------------------------------------------------");
                            Console.ReadKey();
                        }
                    break;
                    case "3":
                        using(BaseConverter converter = new BaseConverter())
                        {
                            var watch = System.Diagnostics.Stopwatch.StartNew();
                            usuarios_sha256 = converter.ToSHA256(usuarios_decrypt, false);
                            watch.Stop();

                            Console.WriteLine("---------------------------------------------------------------------");
                            Console.WriteLine("Elaspsed time to convert base to SHA256: " + watch.Elapsed.TotalMilliseconds + " Miliseconds");
                            Console.WriteLine("---------------------------------------------------------------------");
                            Console.ReadKey();
                        }
                    break;
                    case "4":
                        using(BaseConverter converter = new BaseConverter())
                        {
                            var watch = System.Diagnostics.Stopwatch.StartNew();
                            usuarios_md5_salted = converter.ToMD5(usuarios_decrypt, true);
                            watch.Stop();

                            Console.WriteLine("-------------------------------------------------------------------------");
                            Console.WriteLine("Elaspsed time to convert base to salted MD5: " + watch.Elapsed.TotalMilliseconds + " Miliseconds");
                            Console.WriteLine("-------------------------------------------------------------------------");
                            Console.ReadKey();
                        }
                    break;
                    case "5":
                        using(BaseConverter converter = new BaseConverter())
                        {
                            var watch = System.Diagnostics.Stopwatch.StartNew();
                            usuarios_sha1_salted = converter.ToSHA1(usuarios_decrypt, true);
                            watch.Stop();

                            Console.WriteLine("--------------------------------------------------------------------");
                            Console.WriteLine("Elaspsed time to convert base to salted SHA1: " + watch.Elapsed.TotalMilliseconds+ " Miliseconds");
                            Console.WriteLine("--------------------------------------------------------------------");
                            Console.ReadKey();
                        }
                    break;
                    case "6":
                        using(BaseConverter converter = new BaseConverter())
                        {
                            var watch = System.Diagnostics.Stopwatch.StartNew();
                            usuarios_sha256_salted = converter.ToSHA256(usuarios_decrypt, true);
                            watch.Stop();

                            Console.WriteLine("-------------------------------------------------------------------");
                            Console.WriteLine("Elaspsed time to convert base to salted SHA256: " + watch.Elapsed.TotalMilliseconds + " Miliseconds");
                            Console.WriteLine("-------------------------------------------------------------------");
                            Console.ReadKey();
                        }
                    break;
                    case "7":
                        using(BaseValidator validator = new BaseValidator())
                        {
                            Usuario temp = new Usuario(); 

                            Console.Clear();
                            Console.Write("User: ");
                            temp.nome = Console.ReadLine();
                            Console.Clear();
                            Console.Write("Password: ");                         
                            temp.senha = SecureString.GetPassword();

                            validator.ValidateMD5(usuarios_md5, temp, false);
                        }
                    break;
                    case "8":
                        using(BaseValidator validator = new BaseValidator())
                        {
                            Usuario temp = new Usuario(); 

                            Console.Clear();
                            Console.Write("User: ");
                            temp.nome = Console.ReadLine();
                            Console.Clear();
                            Console.Write("Password: ");
                            temp.senha = SecureString.GetPassword();

                            validator.ValidateSHA1(usuarios_sha1, temp, false);
                        }
                    break;
                    case "9":
                        using(BaseValidator validator = new BaseValidator())
                        {
                            Usuario temp = new Usuario(); 

                            Console.Clear();
                            Console.Write("User: ");
                            temp.nome = Console.ReadLine();
                            Console.Clear();
                            Console.Write("Password: ");
                            temp.senha = SecureString.GetPassword();

                            validator.ValidateSHA256(usuarios_sha256, temp, false);
                        }
                    break;
                    case "10":
                        using(BaseValidator validator = new BaseValidator())
                        {
                            Usuario temp = new Usuario(); 

                            Console.Clear();
                            Console.Write("User: ");
                            temp.nome = Console.ReadLine();
                            Console.Clear();
                            Console.Write("Password: ");                         
                            temp.senha = SecureString.GetPassword();

                            validator.ValidateMD5(usuarios_md5_salted, temp, true);
                        }
                    break;
                    case "11":
                        using(BaseValidator validator = new BaseValidator())
                        {
                            Usuario temp = new Usuario(); 

                            Console.Clear();
                            Console.Write("User: ");
                            temp.nome = Console.ReadLine();
                            Console.Clear();
                            Console.Write("Password: ");
                            temp.senha = SecureString.GetPassword();

                            validator.ValidateSHA1(usuarios_sha1_salted, temp, true);
                        }
                    break;
                    case "12":
                        using(BaseValidator validator = new BaseValidator())
                        {
                            Usuario temp = new Usuario(); 

                            Console.Clear();
                            Console.Write("User: ");
                            temp.nome = Console.ReadLine();
                            Console.Clear();
                            Console.Write("Password: ");
                            temp.senha = SecureString.GetPassword();

                            validator.ValidateSHA256(usuarios_sha256_salted, temp, true);
                        }
                    break;
                    case "20":
                        Console.Clear();
                        Console.WriteLine(" ----------------------------------------------------------------------------------------------");
                        Console.WriteLine("|                   Usuario                    |                    Senha                      |");
                        Console.WriteLine(" ----------------------------------------------------------------------------------------------");
                        foreach(var item in usuarios_decrypt){
                            Console.WriteLine("|" + item.nome + "|" + item.senha + "|");
                        }
                        Console.WriteLine(" ----------------------------------------------------------------------------------------------");
                        Console.ReadKey();
                    break;
                    case "q":
                        Console.Clear();
                        exit = true;     
                    break;
                    default:
                        Console.WriteLine("Bad instruction");
                        Console.ReadKey();
                    break;
                }
            }
        }
    }
}
