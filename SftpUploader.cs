using Renci.SshNet;

namespace SCAScanner;

/// <summary>
/// Handles SFTP upload of generated report files to a remote server.
/// Supports both password and SSH key-based authentication.
/// </summary>
public class SftpUploader
{
    /// <summary>
    /// Uploads a list of local files to an SFTP server.
    /// </summary>
    /// <param name="config">SFTP configuration (host, credentials, remote path)</param>
    /// <param name="filePaths">List of local file paths to upload</param>
    /// <param name="reporter">Optional reporter for logging upload progress</param>
    /// <exception cref="InvalidOperationException">If connection fails, authentication fails, or any file fails to upload</exception>
    public async Task UploadFilesAsync(SftpConfig config, List<string> filePaths, IReporter reporter)
    {
        if (!config.Enabled)
        {
            return;
        }

        config.Validate();

        reporter?.PrintInfo($"Connecting to SFTP server: {config.Host}:{config.Port}...");

        ConnectionInfo connectionInfo;
        try
        {
            connectionInfo = CreateConnectionInfo(config);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to configure SFTP connection: {ex.Message}", ex);
        }

        using (var client = new SftpClient(connectionInfo))
        {
            try
            {
                client.Connect();
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to connect to SFTP server {config.Host}:{config.Port}: {ex.Message}", ex);
            }

            reporter?.PrintInfo($"Successfully connected to SFTP server. Remote path: {config.RemotePath}");

            // Create remote directory if it doesn't exist
            try
            {
                if (!client.Exists(config.RemotePath))
                {
                    client.CreateDirectory(config.RemotePath);
                    reporter?.PrintInfo($"Created remote directory: {config.RemotePath}");
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to access remote path '{config.RemotePath}': {ex.Message}", ex);
            }

            int successCount = 0;
            int failureCount = 0;
            var failures = new List<string>();

            // Upload each file
            foreach (var filePath in filePaths)
            {
                if (!File.Exists(filePath))
                {
                    reporter?.PrintWarning($"Local file not found, skipping: {filePath}");
                    failureCount++;
                    failures.Add($"{filePath} (file not found)");
                    continue;
                }

                try
                {
                    string fileName = Path.GetFileName(filePath);
                    string remotePath = $"{config.RemotePath.TrimEnd('/')}/{fileName}";

                    using (var fileStream = File.OpenRead(filePath))
                    {
                        client.UploadFile(fileStream, remotePath, true);
                    }

                    reporter?.PrintInfo($"Uploaded: {fileName}");
                    successCount++;
                }
                catch (Exception ex)
                {
                    reporter?.PrintWarning($"Failed to upload {filePath}: {ex.Message}");
                    failureCount++;
                    failures.Add($"{filePath} ({ex.Message})");
                }
            }

            client.Disconnect();

            // If any files failed to upload, throw an exception (all-or-nothing semantic)
            if (failureCount > 0)
            {
                string failureDetails = string.Join(", ", failures);
                throw new InvalidOperationException($"SFTP upload completed with errors. Uploaded: {successCount}, Failed: {failureCount}. Details: {failureDetails}");
            }

            reporter?.PrintInfo($"SFTP upload complete. {successCount} file(s) uploaded successfully.");
        }
    }

    /// <summary>
    /// Creates a ConnectionInfo object based on config (password or key-based auth).
    /// </summary>
    private ConnectionInfo CreateConnectionInfo(SftpConfig config)
    {
        var authMethods = new List<AuthenticationMethod>();

        // Try password auth first
        if (!string.IsNullOrEmpty(config.Password))
        {
            authMethods.Add(new PasswordAuthenticationMethod(config.User, config.Password));
        }

        // Try key-based auth
        if (!string.IsNullOrEmpty(config.KeyPath))
        {
            if (!File.Exists(config.KeyPath))
            {
                throw new InvalidOperationException($"SSH private key file not found: {config.KeyPath}");
            }

            try
            {
                var keyFile = new PrivateKeyFile(config.KeyPath);
                authMethods.Add(new PrivateKeyAuthenticationMethod(config.User, keyFile));
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to load SSH private key: {ex.Message}", ex);
            }
        }

        if (authMethods.Count == 0)
        {
            throw new InvalidOperationException("No authentication method configured (neither password nor key)");
        }

        return new ConnectionInfo(config.Host, config.Port, config.User, [.. authMethods]);
    }
}
