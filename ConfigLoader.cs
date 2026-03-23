namespace SCAScanner;

/// <summary>
/// Utility class for loading and managing SCA Scanner configuration files.
/// Handles loading from YAML files, writing templates, and merging with defaults.
/// </summary>
public static class ConfigLoader
{
    /// <summary>
    /// Default config file name to search for in the working directory.
    /// </summary>
    private const string DefaultConfigFileName = "config.yml";

    /// <summary>
    /// Loads configuration from a file, with fallback to default location.
    /// </summary>
    /// <param name="configPath">Explicit config file path (overrides default search). If null, tries default location.</param>
    /// <param name="reporter">Optional reporter for logging which config file was loaded.</param>
    /// <returns>Loaded ScannerConfig or default if not found.</returns>
    /// <exception cref="InvalidOperationException">If config file exists but is invalid YAML.</exception>
    public static ScannerConfig LoadConfig(string? configPath, IReporter? reporter = null)
    {
        string? actualPath = null;

        if (!string.IsNullOrEmpty(configPath))
        {
            // Use explicitly provided config path
            actualPath = configPath;
        }
        else if (File.Exists(DefaultConfigFileName))
        {
            // Fall back to default config.yml if it exists in working directory
            actualPath = DefaultConfigFileName;
        }

        if (actualPath is null)
        {
            // No config file found, use defaults
            return ScannerConfig.CreateDefault();
        }

        // Load and parse the config file
        try
        {
            ScannerConfig config = ScannerConfig.LoadFromFile(actualPath);
            reporter?.PrintInfo($"Loaded configuration from: {Path.GetFullPath(actualPath)}");
            return config;
        }
        catch (InvalidOperationException ex)
        {
            throw new InvalidOperationException($"Error loading config file '{actualPath}': {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Writes a template config file with all available options.
    /// </summary>
    /// <param name="outputPath">Where to write the template. If null or empty, uses default "config.yml".</param>
    /// <param name="reporter">Optional reporter for logging the output path.</param>
    /// <exception cref="InvalidOperationException">If template cannot be written.</exception>
    public static void WriteTemplate(string? outputPath, IReporter? reporter = null)
    {
        string targetPath = string.IsNullOrEmpty(outputPath) ? DefaultConfigFileName : outputPath;

        try
        {
            ScannerConfig.WriteTemplate(targetPath);
            string fullPath = Path.GetFullPath(targetPath);
            reporter?.PrintInfo($"Template config file created: {fullPath}");
        }
        catch (InvalidOperationException ex)
        {
            throw new InvalidOperationException($"Failed to write config template: {ex.Message}", ex);
        }
    }
}
