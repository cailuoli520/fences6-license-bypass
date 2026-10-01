// Stardock.ApplicationServices - replacement shim for Fences 6 (6.5.2.7)
// ---------------------------------------------------------------------------
// Drop-in, API-compatible stand-in for Stardock's SAS glue assembly. Fences.exe
// consumes only four public types from it (LicenseState, LicenseInformation,
// Result, Sas) plus a few delegates/enums/UiDefinition; everything else is P/Invoke
// plumbing that Fences never calls directly.
//
// The shim reports a permanent, fully validated licence, so no signed SAS
// License.sig is needed and the activation UI never appears. The real
// SdAppServices_*.dll is never invoked.
//
// Assembly identity is deliberately the version Fences.exe references (1.10.4.128),
// so the loader binds to this file without any binding redirect in Fences.exe.config.
//
// Build (see build_shim.ps1): csc /target:library /out:Stardock.ApplicationServices.dll
//
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Stardock.ApplicationServices
{
    // ---- enums -------------------------------------------------------------
    public enum Result
    {
        NotComplete = 2,
        NoData = 1,
        Success = 0,
        NullParameter = -1,
        BufferToSmall = -2,
        Uninitialized = -3,
        ItemNotFound = -4,
        UnknownError = -5,
        InvalidModule = -7,
        InvalidPackage = -8,
        InvalidParameter = -9,
        InvalidOperation = -10,
        InvalidResponse = -11,
        ApplicationClose = -12,
        AccessDenied = -13,
        UiUnknown = 100,
        UiQuit = 101,
        UiExternal = 102,
        UiManualClose = 103,
        UiTimeout = 104,
        UiYes = 105,
        UiNo = 106,
        ActivateRequiresValidation = -201,
        ActivateNotEligible = -202,
        ActivateNoConnection = -203,
        ActivateLoginFailed = -204,
        ActivateUnknown = -205,
        ActivateEmailMismatch = -206,
        ActivateMachineMismatch = -207,
        TimeMismatch = -208,
        Deactivated = -209,
        CustomMessage = -210,
        InvalidSerial = -211,
        InvalidLicenseFile = -212,
        LockedOut = -213,
        UpgradeRequired = -214,
        TooManyRegistrations = -215,
        LicenseExpired = -216,
        ActivateLimitExceeded = -217
    }

    public enum LicenseState
    {
        Unknown = 0,
        NoLicense = 1,
        TrialExpired = 2,
        SubscriptionExpired = 3,
        LicenseRevoked = 4,
        Authorized = 10,
        GracePeriod = 11,
        Trial = 12,
        Subscription = 13,
        PermanentLicense = 14
    }

    public enum UiType { Dialog, Popup, Frame }

    public enum TimestampType
    {
        Initialize, TrialStart, TrialExpire, Activation, SubscriptionExpire, AnyExpire
    }

    public enum ScheduleFlags
    {
        Product = 1,
        Update = 2,
        Marketing = 3,
        Background = 4,
        Full = 65535
    }

    // ---- licence carrier ---------------------------------------------------
    public class LicenseInformation
    {
        private static LicenseInformation s_noLicense;
        private static LicenseInformation s_permanent;
        private LicenseState _state;
        private DateTime _activation;
        private DateTime _expiration;

        public LicenseState State
        {
            get { return _state; }
            private set { _state = value; }
        }

        public DateTime Activation
        {
            get { return _activation; }
            private set { _activation = value; }
        }

        public DateTime Expiration
        {
            get { return _expiration; }
            private set { _expiration = value; }
        }

        public static LicenseInformation NoLicense
        {
            get
            {
                if (s_noLicense == null)
                    s_noLicense = new LicenseInformation(LicenseState.NoLicense, DateTime.MaxValue, DateTime.MinValue);
                return s_noLicense;
            }
        }

        public static LicenseInformation PermanentLicense
        {
            get
            {
                if (s_permanent == null)
                    s_permanent = new LicenseInformation(LicenseState.PermanentLicense, DateTime.MinValue, DateTime.MaxValue);
                return s_permanent;
            }
        }

        internal LicenseInformation(LicenseState state, DateTime activation, DateTime expiration)
        {
            State = state;
            Activation = activation;
            Expiration = expiration;
        }
    }

    // ---- UI description ----------------------------------------------------
    public class UiDefinition
    {
        public string Url { get; set; }
        public UiType Type { get; set; }
        public int Width { get; set; }
        public int Height { get; set; }
        public int TimeoutSeconds { get; set; }
        public int TitleBarHeight { get; set; }
        public bool AlwaysOnTop { get; set; }
    }

    // ---- the glue class ----------------------------------------------------
    public class Sas
    {
        // NOTE: both delegates are NESTED types in the original assembly
        // (Stardock.ApplicationServices.Sas+LicenseChangedDelegate etc).
        // Fences looks them up by that exact path, so they must stay nested here.
        public delegate void LicenseChangedDelegate();

        public delegate void DownloadUpdateDelegate(bool complete, ulong downloadedBytes, ulong totalBytes);

        private static LicenseChangedDelegate s_licenseChanged;
        private static readonly Dictionary<string, string> s_cache = new Dictionary<string, string>();

        // -------- success ---------------------------------------------------
        public static bool IsResultSuccess(Result res) { return res >= Result.Success; }

        public static Result Initialize(int productId, string productName, string companyName, string productVersion)
        {
            return Result.Success;
        }

        /// <summary>Core licence query. Fences calls this for FeatureID.All, whose
        /// value is the SAS product id 2688. Always a permanent licence.</summary>
        public static Result VerifyLicense(int productId, out LicenseInformation license)
        {
            license = LicenseInformation.PermanentLicense;
            return Result.Success;
        }

        public static Result VerifyLicense(int productId, out LicenseState state, out DateTime activation, out DateTime expiration)
        {
            state = LicenseState.PermanentLicense;
            activation = DateTime.MinValue;
            expiration = DateTime.MaxValue;
            return Result.Success;
        }

        public static Result ValidateLicense() { return Result.Success; }

        // -------- benign no-ops ---------------------------------------------
        public static bool TryGetProperty(string key, out string value) { return s_cache.TryGetValue(key, out value); }

        public static IEnumerable<KeyValuePair<string, string>> GetProperties()
        {
            return new List<KeyValuePair<string, string>>(s_cache);
        }

        public static Result GetUiDefinition(string key, out UiDefinition uiDef)
        {
            uiDef = new UiDefinition();
            return Result.Success;
        }

        public static Result ReadPackageFile(string fileName, out byte[] data) { data = new byte[0]; return Result.Success; }
        public static Result ReadPackageFileLocalized(string fileName, out byte[] data) { data = new byte[0]; return Result.Success; }

        public static Result SetStoredCredentials(string email, string password) { return Result.Success; }

        public static Result GetStoredCredentials(out string email, out string password)
        {
            email = string.Empty; password = string.Empty;
            return Result.Success;
        }

        public static bool TryGetStoredTrialEmail(out string email) { email = string.Empty; return false; }
        public static Result SetStoredTrialEmail(string email) { return Result.Success; }

        public static bool TryGetCacheValue(string key, out string value) { return s_cache.TryGetValue(key, out value); }

        public static Result SetCacheValue(string key, string value)
        {
            s_cache[key] = value;
            return Result.Success;
        }

        public static Result DetectConnection(out bool connected) { connected = false; return Result.Success; }

        public static Result StartTrial(string email) { return Result.Success; }
        public static Result ActivateAccount(string email, string password) { return Result.Success; }
        public static Result ActivateSerial(string email, string serial) { return Result.Success; }

        public static Result SaveOfflineAccountActivationFile(string email, string password, string filename) { return Result.Success; }
        public static Result SaveOfflineSerialActivationFile(string email, string serial, string filename) { return Result.Success; }
        public static Result OfflineActivate(string filename) { return Result.Success; }
        public static Result AddFileLog(string filename) { return Result.Success; }

        public static bool TryGetProductDescription(int productId, out string description)
        {
            description = "Fences 6";
            return true;
        }

        public static IEnumerable<string> GetProductDescriptions()
        {
            return new List<string>(new string[] { "Fences 6" });
        }

        public static Result GetTimestamp(int productId, TimestampType type, out long time)
        {
            time = 0L;
            return Result.Success;
        }

        public static string GetTrialRequestToken() { return string.Empty; }
        public static string GetCustomErrorMessage() { return string.Empty; }
        public static string GetSignatureLocation() { return string.Empty; }
        public static string GetAccountUserName() { return string.Empty; }
        public static Result SetAccountUserName(string userName) { return Result.Success; }
        public static Result StartScheduler(ScheduleFlags flags) { return Result.Success; }
        public static Result StopScheduler() { return Result.Success; }

        // The activation / welcome UI must never come up.
        public static Result ShowUi(string uiKey) { return Result.Success; }
        public static Result ShowUiAsync(string uiKey) { return Result.Success; }
        public static Result ShowHostedUi(string uiKey, IntPtr owner) { return Result.Success; }

        public static Result DeactivateLocalMachine() { return Result.Success; }
        public static Result DeactivateRegistration(string email, string serial, string password) { return Result.Success; }

        public static Result SetLicenseChangedCallback(LicenseChangedDelegate callback)
        {
            s_licenseChanged = callback;
            return Result.Success;
        }

        public static string GetAffiliate() { return string.Empty; }
        public static string GetActivationType() { return "Permanent"; }

        public static bool GetActivationInfo(out int activationId, out bool autoRenew)
        {
            activationId = 0;
            autoRenew = false;
            return false;
        }

        public static string GetSASVersion() { return "1.10.10.161"; }

        public static Result SetUserOption(ScheduleFlags flags, bool option) { return Result.Success; }

        public static Result GetUserOption(ScheduleFlags flags, out bool option)
        {
            option = true;
            return Result.Success;
        }

        public static Result DownloadUpdate(DownloadUpdateDelegate callback)
        {
            if (callback != null) callback(true, 0UL, 0UL);
            return Result.Success;
        }

        public static Result InstallUpdate() { return Result.Success; }
        public static Result ManualUpdateCheck(IntPtr owner) { return Result.Success; }
        public static string GetSurveyUrl() { return string.Empty; }
    }
}
