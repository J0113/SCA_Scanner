namespace SCAScanner;

/// <summary>
/// Immutable configuration for SFTP server connection and upload settings.
/// Supports both password and SSH key-based authentication.
/// </summary>
public class SftpConfig
{
    /// <summary>
    /// SFTP server hostname or IP address (required if SFTP is enabled).
    /// </summary>
    public string? Host { get; init; }

    /// <summary>
    /// SFTP server port (default: 22).
    /// </summary>
    public int Port { get; init; } = 22;

    /// <summary>
    /// Username for SFTP authentication.
    /// </summary>
    public string? User { get; init; }

    /// <summary>
    /// Password for SFTP authentication (null if using key-based auth).
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Path to SSH private key file for key-based authentication (null if using password auth).
    /// </summary>
    public string? KeyPath { get; init; }

    /// <summary>
    /// Remote directory path where files will be uploaded (default: /).
    /// </summary>
    public string RemotePath { get; init; } = "/";

    /// <summary>
    /// Returns true if SFTP upload is enabled (Host is provided).
    /// </summary>
    public bool Enabled => !string.IsNullOrEmpty(Host);

    /// <summary>
    /// Validates that authentication is properly configured.
    /// </summary>
    /// <exception cref="ArgumentException">If neither password nor key path is provided.</exception>
    public void Validate()
    {
        if (Enabled && string.IsNullOrEmpty(Password) && string.IsNullOrEmpty(KeyPath))
        {
            throw new ArgumentException("SFTP authentication requires either --sftp-pass or --sftp-key");
        }
    }
}
