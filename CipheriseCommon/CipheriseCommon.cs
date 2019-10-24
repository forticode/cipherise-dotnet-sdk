using System;

using System.Diagnostics;
using System.Text;

using System.IO;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;         //SHA256Managed

using System.Threading;
using System.Threading.Tasks;
using System.Runtime.Serialization;

#if !CIPHERISE_COMMON_NO_JSON
using System.Runtime.Serialization.Json;
#endif //!CIPHERISE_COMMON_NO_JSON

using NumberDictionary = System.Collections.Generic.Dictionary<string, string>;

namespace Cipherise.Common
{
    internal static class CipheriseCommon
    {
        static CipheriseCommon()
        {
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
        }

        public static void TraceAlways(this String strMessage, string strPrepend = "")
        {
            //if (Cipherise.GetTraceLevel() >= TraceLevel.Info)
            Trace.TraceInformation(strPrepend + strMessage);
        }

        public static string TraceError(this String strMessage, string strPrepend = "")
        {
            string strRet = "";
            if (CipheriseSP.GetTraceLevel() >= TraceLevel.Error)
            {
                strRet = strPrepend + strMessage;
                Trace.TraceError(strRet);
            }
            return strRet;
        }

        public static void TraceWarning(this String strMessage, string strPrepend = "")
        {
            if (CipheriseSP.GetTraceLevel() >= TraceLevel.Warning)
                Trace.TraceWarning(strPrepend + strMessage);
        }

        public static void TraceVerbose(this String strMessage, string strPrepend = "")
        {
            if(CipheriseSP.GetTraceLevel() >= TraceLevel.Verbose)
                Trace.TraceInformation("VERBOSE: " + strPrepend + strMessage);
        }

        public static string GetModulePath<TClass>(this TClass ThisClass)
        {
            return Path.GetDirectoryName(typeof(TClass).Module.FullyQualifiedName);
        }

        public static void TraceDebug(this String strMessage, string strPrepend = "")
        {
            Debug.WriteLine(strPrepend + strMessage);
        }

        public static void TraceException(this Exception e, string strLabel = null, bool bStackTrace = true)
        {
            string strText = "Exception caught";
            if (strLabel.IsStringValid())
                strText += " in " + strLabel;
            strText += ": ";

            Trace.TraceError(strText + e.Message);

            if (e.InnerException != null)
                e.InnerException.TraceException(strLabel, false);
            else
                Trace.TraceError("Exception caught: {0}", e.GetType());

            if (bStackTrace)
                Trace.TraceError("{0}", e.StackTrace);
        }

        public static string CatchMessage(this Exception e)
        {
            return "Caught " + e.GetType().ToString() + ": " + e.Message + "\n" + e.StackTrace;
        }

        public static bool IsStringValid(this string s)
        {
            return (String.IsNullOrEmpty(s) || String.IsNullOrWhiteSpace(s)) == false;
        }

        //-------------------------------------------------------------------------
        private static readonly uint[] _lookup32 = CreateLookup32();
        private static uint[] CreateLookup32()
        {
            uint[] result = new uint[256];
            for (int i = 0; i < 256; i++)
            {
                string s = i.ToString("x2");
                result[i] = ((uint)s[0]) + ((uint)s[1] << 16);
            }
            return result;
        }
        public static string ToHexString(this byte[] bytes)  //Fastest!!
        {
            uint[] lookup32 = _lookup32;
            char[] result = new char[bytes.Length * 2];
            //uint val;
            for (int i = 0; i < bytes.Length; i++)
            {
                uint val = lookup32[bytes[i]];
                result[2 * i] = (char)val;
                result[2 * i + 1] = (char)(val >> 16);
            }
            return new string(result);
        }

        public static string ToHexString2(this byte[] barray)  //Almost as fast, but doenst rely on _lookup32
        {
            char[] c = new char[barray.Length * 2];
            byte b;
            for (int i = 0; i < barray.Length; ++i)
            {
                b = ((byte)(barray[i] >> 4));
                c[i * 2] = (char)(b > 9 ? b + 0x37 : b + 0x30);
                b = ((byte)(barray[i] & 0xF));
                c[i * 2 + 1] = (char)(b > 9 ? b + 0x37 : b + 0x30);
            }
            return new string(c);
        }

        public static byte[] ToByteArray(this string strHex)
        {
            int NumberChars = strHex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(strHex.Substring(i, 2), 16);
            return bytes;
        }
        //-------------------------------------------------------------------------
        //return the SHA256 of the string as hex string
        public static string SHA256(this string strClear, bool bForceLowercaseBeforeSHA = false)
        {
            string strConvert = bForceLowercaseBeforeSHA ? strClear.ToLower() : strClear;

            //Not FIPS compliant
            //SHA256Managed sha256 = new SHA256Managed();

            //SHA256CryptoServiceProvider FIPS compliant
            SHA256 sha256 = new SHA256CryptoServiceProvider();
            byte[] aHashData = sha256.ComputeHash(Encoding.UTF8.GetBytes(strConvert));
            return ToHexString(aHashData);
        }
        //-------------------------------------------------------------------------
        public static bool CompareNoCase(this string strText, string strCompare)
        {
            return (String.Compare(strText, strCompare, true) == 0);
        }

        //-------------------------------------------------------------------------
        public static bool IsValid(this string strText)
        {
            return (string.IsNullOrEmpty(strText) == false);
        }
        //-------------------------------------------------------------------------
        public static bool IsNotValid(this string strText)
        {
            return string.IsNullOrEmpty(strText);
        }
        //-------------------------------------------------------------------------
        public static bool IsValidWithCount(this NumberDictionary oND, int iCount)
        {
            return ((oND != null) && (oND.Count == iCount));
        }
        //-------------------------------------------------------------------------
        public static string GetExceptionSource(this Exception e)
        {
            string strRet = "[Unknown exception source]";
            try
            {
                // Get stack trace for the exception with source file information
                StackTrace trace = new StackTrace(e, true);
                StackFrame frame = trace.GetFrame(0);
                int iLine = frame.GetFileLineNumber();
                string strFilename = frame.GetFileName();

                if(strFilename.IsValid())
                    strRet = string.Format("{0}({1})", strFilename, iLine);
            }
            catch (Exception) {}
            return strRet;
        }
        //-------------------------------------------------------------------
        //Format String:   "hey {0}".FS("there!");
        public static string FS(this string strFormat, params object[] list)
        {
            return String.Format(strFormat, list);
        }
        //-------------------------------------------------------------------
        private static RandomNumberGenerator s_RNG = null;
        private static readonly object s_RNGLock = new object();
        public static void FillRandom(this byte[] array)
        {
            lock (s_RNGLock)  //s_RNG may not be thread safe. Implementation dependant.
            {
                if (s_RNG == null)
                    s_RNG = RandomNumberGenerator.Create();
                s_RNG.GetBytes(array);
            }
        }
        //-------------------------------------------------------------------
        private delegate bool ProcessJSONDelegate(HttpStatusCode eStatus, Stream stream);

        /// <exception cref="Exception"></exception>
        private static async Task<bool> ForticodeRequest(string strRequestURI, ProcessJSONDelegate ProcessJSON, string strPostJSON = null, string strSessionID = null)
        {
            HttpWebResponse response = null;
            try
            {
                strRequestURI.TraceVerbose("CONNECTING: ");
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(new System.Uri(strRequestURI, UriKind.Absolute));

                request.ContentType = "application/json";
                request.Method = "GET";
                request.Accept = "*/*";

                if (string.IsNullOrEmpty(strSessionID) == false)
                    request.Headers.Add("sessionId", strSessionID);

                if (strPostJSON != null)
                {
                    request.Method = "POST";
                    if (strPostJSON != "")
                    {
                        using (StreamWriter streamWriter = new StreamWriter(request.GetRequestStream()))
                        {
#if DEBUG
                            strPostJSON.TraceVerbose("SEND: ");
#endif  //DEBUG
                            streamWriter.Write(strPostJSON);
                        }
                    }
                }

                response = await request.GetResponseAsync() as HttpWebResponse;
            }
            catch (System.Net.WebException e)
            {
                if (e.Response is HttpWebResponse)
                    response = (e.Response as HttpWebResponse);

                else if (e.InnerException is System.Net.Sockets.SocketException)
                    e.InnerException.Message.TraceWarning();

                else if (!string.IsNullOrEmpty(e.Message))
                {
                    e.Message.TraceWarning();

                    System.Exception I = e;
                    while (I.InnerException != null)
                    {
                        if(!string.IsNullOrEmpty(I.InnerException.Message))
                            I.InnerException.Message.TraceWarning();

                        I = I.InnerException;
                    }
                }
                //else
                //    throw e;
            }

            bool bRet = false;
            if (response != null)
            {
                using (response)
                {
                    HttpStatusCode eStatus = response.StatusCode;
                    using (Stream stream = response.GetResponseStream())
                    {
                        bRet = ProcessJSON(eStatus, stream);
                    }
                }

            }
            return bRet;
        }

#if !CIPHERISE_COMMON_NO_JSON

        private static DataContractJsonSerializer GetJsonSerializer<T>()
        {
            DataContractJsonSerializerSettings jsonSettings = new DataContractJsonSerializerSettings();
            jsonSettings.UseSimpleDictionaryFormat = true;

            return new DataContractJsonSerializer(typeof(T), jsonSettings);
        }

        public static T FromJSON<T>(Stream stream) where T : CipheriseError, new()
        {
            string strExpcetionError = null;
            try
            {
                object objResponse = GetJsonSerializer<T>().ReadObject(stream);
                return (T)objResponse;
            }
            catch (Exception e) { strExpcetionError = e.Message; /*e.CatchMessage().TraceError();*/ }

            if (strExpcetionError == null)
                return default(T);

            T retT = new T();
            retT.SetError(strExpcetionError);
            return retT;
        }

        public static string ToJSON<T>(this T obj) where T : class
        {
            using (MemoryStream stream = new MemoryStream())
            {
                GetJsonSerializer<T>().WriteObject(stream, obj);
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }

        public static Stream ToStream(this string str, Encoding enc = null)
        {
            //Usgae: using (Stream stream = someStr.ToStream(enc))
            enc = enc ?? Encoding.UTF8;
            return new MemoryStream(enc.GetBytes(str ?? ""));
        }

        public static T FromJSON<T>(this string strJSON, Encoding enc = null) where T : CipheriseError, new()
        {
            using (Stream stream = strJSON.ToStream(enc))
            {
                T OutData = FromJSON<T>(stream);
                if ((OutData != null) && (OutData.Validate()))
                    return OutData;
            }
            String.Format("Invalid data: '{0}'", typeof(T)).TraceError();
            return null;
        }

        public delegate void UpdateOut<T>(ref T t);

        public static async Task<T> CipheriseRequest<T>(this string strRequestURI, UpdateOut<T> UpdateCB = null) where T : CipheriseError, new()
        {
            return await CipheriseRequest<T>(strRequestURI, HttpStatusCode.OK, null, null, UpdateCB);
        }

        public static async Task<T> CipheriseRequest<T>(this string strRequestURI, string strSessionID, UpdateOut<T> UpdateCB = null) where T : CipheriseError, new()
        {
            return await CipheriseRequest<T>(strRequestURI, HttpStatusCode.OK, null, strSessionID, UpdateCB);
        }

        public static async Task<T> CipheriseRequest<T>(this string strRequestURI, string strPostJSON, string strSessionID, UpdateOut<T> UpdateCB = null) where T : CipheriseError, new()
        {
            return await CipheriseRequest<T>(strRequestURI, HttpStatusCode.OK, strPostJSON, strSessionID, UpdateCB);
        }

        public static async Task<T> CipheriseRequest<T>(this string strRequestURI, HttpStatusCode eExpectedStatus, string strPostJSON, string strSessionID = null, UpdateOut<T> UpdateCB = null) where T : CipheriseError, new()
        {
            try
            {
                T OutData = default(T);  //Lambas cant capture the out/ref Data,  use a temp instead.
                ProcessJSONDelegate JSONDelegate = (HttpStatusCode eStatus, Stream stream) =>
                {
                    if (eExpectedStatus != eStatus)
                    {
                        String.Format("Invalid HTTP status code: '{0}'.  Expecting: '{1}'", eStatus.ToString(), eExpectedStatus.ToString()).TraceWarning();

                        bool bRet = false;
                        CipheriseError E = FromJSON<CipheriseError>(stream);
                        if ((E != null) && E.HasError())
                        {
                            E.GetError().TraceError("Cipherise JSON Error: ");

                            OutData = new T();
                            if (UpdateCB != null)
                                UpdateCB(ref OutData);
                            OutData.SetError(ref E);
                            bRet = true; //Caller must check T.HasError()
                        }
#if DEBUG
                        {
                            if (stream.CanSeek)
                                stream.Seek(0, SeekOrigin.Begin);
                            using (StreamReader streamReader = new StreamReader(stream))
                            {
                                string responseFromServer = streamReader.ReadToEnd();
                                responseFromServer.TraceError("Invalid response: ");
                                streamReader.Close();
                            }
                        }
#endif
                        return bRet;
                    }

                    //bool bEmptyResponse2 = (OutData is EmptyResponse);
                    bool bEmptyResponse = (typeof(EmptyResponse).IsAssignableFrom(typeof(T)));
                    if (bEmptyResponse)
                    {
                        OutData = new T();  //return an empty response instead of NULL
                        if(UpdateCB != null)
                            UpdateCB(ref OutData);
                    }
                    else
                    {
#if DEBUG
                        {
                            byte[] aData = null;
                            using (MemoryStream ms = new MemoryStream())
                            {
                                stream.CopyTo(ms);
                                aData = ms.ToArray();
                                ms.Seek(0, SeekOrigin.Begin);

                                StreamReader reader = new StreamReader(ms);
                                reader.ReadToEnd().TraceVerbose("RESPONSE:  ");
                            }
                            stream = new MemoryStream(aData);
                        }
#endif  //DEBUG

                        bool bValid = false;
                        OutData = FromJSON<T>(stream);
                        if (OutData != null)
                        {
                            if (UpdateCB != null)
                                UpdateCB(ref OutData);

                            bValid = OutData.Validate();
                        }

                        if (bValid == false)
                        {
                            String.Format("Invalid data: '{0}'", typeof(T)).TraceError();
                            return false;
                        }
                    }
                    return true;
                };

                bool bRequest = await ForticodeRequest(strRequestURI, JSONDelegate, strPostJSON, strSessionID);
                if (bRequest)
                    return OutData;
            }
            catch (Exception e) { e.CatchMessage().TraceError(); }
            return null;
        }

        public interface IValidate
        {
            bool Validate();
        }

        //For responses with a Cipherise Error
        [DataContract]
        public class CipheriseError : IValidate
        {
            [DataMember(Name = "error", EmitDefaultValue = false)]
            public bool m_bError { get; set; } = default(bool);

            [DataMember(Name = "error_code", EmitDefaultValue = false)]
            public int m_iError { get; set; } = 0;

            [DataMember(Name = "error_message", EmitDefaultValue = false)]
            public string m_strError { get; set; } = default(string);

            [DataMember(Name = "logId", EmitDefaultValue = false)]
            public string m_strServerLoggingId { get; set; } = default(string);

            //  These are OPTIONAL and come from direct enrolment
            [DataMember(Name = "enrolmentErrorCode", EmitDefaultValue = false)]
            public int m_iAppErrorCode { get; set; } = 0;

            [DataMember(Name = "enrolmentErrorMsg", EmitDefaultValue = false)]
            public string m_strAppErrorMsg { get; set; } = default(string);

            [DataMember(Name = "failReason", EmitDefaultValue = false)]
            public string m_strAppFailReason { get; set; } = default(string);
            //  End OPTIONAL stuff

            public virtual bool Validate()
            {
                return HasError() == false;
            }

            public virtual bool HasError()
            {
                return (    (m_bError              && m_strError.IsValid())
                        || ((m_iAppErrorCode != 0) && (m_strAppFailReason.IsValid() || m_strAppErrorMsg.IsValid()))     );
            }

            public virtual string GetError()
            {
                // If there is an App error message, return that in preference.
                if (m_iAppErrorCode != 0)
                {
                    if (!string.IsNullOrEmpty(m_strAppFailReason))
                        return m_strAppFailReason;
                    else if (!string.IsNullOrEmpty(m_strAppErrorMsg))
                        return m_strAppErrorMsg;
                }
                return m_strError;
            }

            public bool ErrorContainsTimeout()
            {
                return GetError().IndexOf("timeOUT", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            public void SetError(string strError)
            {
                m_strError = strError;
                m_bError = String.IsNullOrEmpty(m_strError) == false;
            }

            public void SetError(ref CipheriseError E)
            {
                m_bError                = E.m_bError;
                m_strError              = E.m_strError;
                m_strServerLoggingId    = E.m_strServerLoggingId;
                m_iAppErrorCode         = E.m_iAppErrorCode;
                m_strAppErrorMsg        = E.m_strAppErrorMsg;
                m_strAppFailReason      = E.m_strAppFailReason;
            }
        }

        //For responses with no JSON
        [DataContract]
        public class EmptyResponse : CipheriseError
        {
            public override bool Validate()
            {
                return true;
            }
        }
#endif //!CIPHERISE_COMMON_NO_JSON

        public static bool WaitFor(this Task T, int iMilliseconds = 0, CancellationToken? token = null)
        {
            bool bRet = false;
            try
            {
                if ((iMilliseconds <= 0) && (token == null))
                {
                    T.Wait();
                    bRet = true;
                }
                else if ((iMilliseconds > 0) && (token == null))
                {
                    bRet = T.Wait(iMilliseconds);
                }
                else if ((iMilliseconds <= 0) && (token != null))
                {
                    T.Wait((CancellationToken)token);
                    bRet = true;
                }
                else
                    bRet = T.Wait(iMilliseconds, (CancellationToken)token);
            }
            catch (Exception)
            {
            }
            return bRet;
        }

        public delegate Task<bool> OnRecvDel(MemoryStream ms, bool bIsText, CancellationToken cancellationToken);

        public static async Task<bool> RecvAsync(this WebSocket WS, OnRecvDel OnRecv, CancellationToken cancellationToken, int iBufferSize = 1024)
        {
            //iBufferSize needs to be larger than the expected recv data
            //  otherwise EOM doesn't occur.
            //iBufferSize = 10;  //BUG??

            bool bRet = false;
            try
            {
                using (var ms = new MemoryStream())
                {
                    ArraySegment<Byte> arrSeg = new ArraySegment<byte>(new Byte[iBufferSize]);
                    while (true)
                    {
                        WebSocketReceiveResult WSR = null;

                        //if ((WS.State != WebSocketState.Open) && (WS.State != WebSocketState.CloseReceived))
                        if ((WS.State != WebSocketState.Open) && (WS.State != WebSocketState.CloseSent))
                            break;

                        //Bug:  If cancellationToken is triggered, the websocket.state ends up being Aborted.
                        //       This denys CloseAsync being called, which gracefully tells the other end of the 
                        //       websocket to close nicely.
                        //       Reported: https://github.com/dotnet/corefx/issues/5200
                        WSR = await WS.ReceiveAsync(arrSeg, cancellationToken);

                        if ((WSR.MessageType == WebSocketMessageType.Close))
                        {
                            //Doesnt get here if cancellationToken is triggered. See comment above.
                            await WS.CloseAsync(WebSocketCloseStatus.NormalClosure, "", cancellationToken);
                            //await WS.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "", CancellationToken.None);
                            break;
                        }

                        //Console.WriteLine("Recv: {0} {1}",WSR.Count, WSR.MessageType);

                        await ms.WriteAsync(arrSeg.Array, 0, WSR.Count, cancellationToken);

                        if (WSR.EndOfMessage)
                        {
                            if (ms.Position > 0)
                            {
                                long nLen = ms.Length;
                                long nPos = ms.Position;

                                ms.Position = 0;
                                ms.SetLength(nPos);

                                if (false == await OnRecv(ms, (WSR.MessageType == WebSocketMessageType.Text), cancellationToken))
                                {
                                    bRet = true;
                                    break;
                                }

                                //Reset stream.
                                ms.SetLength(nPos);
                                ms.Position = 0;
                            }
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
                //Do nothing;
                //bRet = false;
            }
            catch (Exception E)
            {
                E.TraceException("RecvAsync");
            }

            return bRet;
        } // RecvAsync

        public class Disposable : IDisposable
        {
            private bool m_bIsDisposed { get; set; } = false;

            protected bool IsDisposed()
            {
                return m_bIsDisposed;
            }

            public void Dispose()  // IDisposable
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }

            private void Dispose(bool bIsDisposing)
            {
                try
                {
                    if (!m_bIsDisposed)
                    {
                        if (bIsDisposing)
                            CleanUpManagedResources();

                        CleanUpNativeResources();
                    }
                }
                finally
                {
                    m_bIsDisposed = true;
                }
            }

            //Derived classes should implemented this:
            protected virtual void CleanUpManagedResources()
            {
            }

            //Derived classes should implemented this:
            protected virtual void CleanUpNativeResources()
            {
            }
            /*
            ~Disposable()
            {
                Dispose(false);
            }
            */
        } // class Disposable

        internal class ConsoleColour : Disposable
        {
            private ConsoleColor m_FC, m_BC;

            public ConsoleColour(ConsoleColor FC, ConsoleColor BC)
            {
                m_FC = Console.ForegroundColor;
                m_BC = Console.BackgroundColor;

                Console.ForegroundColor = FC;
                Console.BackgroundColor = BC;
            }

            public ConsoleColour(ConsoleColor FC)
            : this(FC, Console.BackgroundColor)
            {
            }

            protected override void CleanUpManagedResources()
            {
                Console.ForegroundColor = m_FC;
                Console.BackgroundColor = m_BC;
            }

        } // class ConsoleColour

    } // class CipheriseCommon

    internal class LogFileTraceListener : TextWriterTraceListener
    {
        public LogFileTraceListener(TextWriter writer, bool bAllOutputOptions = true, string strName = "")
        : base(writer, strName)
        {
            m_TraceOutputOptionsCache = (TraceOptions)0x8000000;

            if (bAllOutputOptions)
                AllOutputOptions();

            base.WriteLine("==========================================");
            TraceEventEx(null, "", TraceEventType.Information, 0, "Opened.");
        }

        public override void Close()
        {
            TraceEventEx(null, "", TraceEventType.Information, 0, "Closed.");
            base.WriteLine("==========================================");
            base.Close();       //Release builds need this to be called before exiting.
        }

        public void AllOutputOptions()
        {
            TraceOutputOptions |= TraceOptions.DateTime;
            TraceOutputOptions |= TraceOptions.ProcessId;
            TraceOutputOptions |= TraceOptions.ThreadId;
        }

        public override void TraceEvent(TraceEventCache eventCache, string strSource, TraceEventType eventType, int id)
        {
            TraceEventEx(eventCache, strSource, eventType, id, "");
        }

        public override void TraceEvent(TraceEventCache eventCache, string strSource, TraceEventType eventType, int id, string strMessage)
        {
            TraceEventEx(eventCache, strSource, eventType, id, strMessage);
        }

        public override void TraceEvent(TraceEventCache eventCache, string strSource, TraceEventType eventType, int id, string strFormat, params object[] args)
        {
            TraceEventEx(eventCache, strSource, eventType, id, String.Format(strFormat, args));
        }

        private void TraceEventEx(TraceEventCache eventCache, string strSource, TraceEventType eventType, int id, string strMessage)
        {
            if (eventCache == null)
                eventCache = new TraceEventCache();

            if (m_TraceOutputOptionsCache != TraceOutputOptions)
            {
                m_TraceOutputOptionsCache = TraceOutputOptions;

                //m_strFormat = "{0} {1}.{2} {3}: {4}";

                m_strFormat = "";
                if ((TraceOutputOptions & TraceOptions.DateTime) == TraceOptions.DateTime)
                    m_strFormat += "{0}";

                if ((TraceOutputOptions & TraceOptions.ProcessId) == TraceOptions.ProcessId)
                {
                    if (m_strFormat.IsValid())
                        m_strFormat += " ";

                    m_strFormat += "{1}";
                    if ((TraceOutputOptions & TraceOptions.ThreadId) == TraceOptions.ThreadId)
                        m_strFormat += ".{2}";
                }
                else if ((TraceOutputOptions & TraceOptions.ThreadId) == TraceOptions.ThreadId)
                {
                    if (m_strFormat.IsValid())
                        m_strFormat += " ";
                    m_strFormat += "{2}";
                }

                if (m_strFormat.IsValid())
                    m_strFormat += " ";
                m_strFormat += "{3}: {4}";
            }

            base.WriteLine(String.Format(m_strFormat, eventCache.DateTime.ToLocalTime().ToString("o"), eventCache.ProcessId, eventCache.ThreadId, eventType.ToString(), strMessage));
        }

        private TraceOptions m_TraceOutputOptionsCache { get; set; }
        private string m_strFormat { get; set; }
    } // LogFileTraceListener
}
