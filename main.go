package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"gopkg.in/yaml.v2"
)

type Config struct {
	KeyVaultURL string            `yaml:"keyVaultURL"`
	SecretMap   map[string]string `yaml:"secretMap"`
}

// Secret struct to hold the map of key-value pairs for secrets
type Secret struct {
	Secrets map[string]string `yaml:"secrets"`
}

func main() {
	// Attempt to read the configuration file
	configFile := "config.yml"
	var config Config
	var err error

	if _, err := os.Stat(configFile); err == nil {
		// Read and unmarshal the configuration data from the YAML file
		configData, err := os.ReadFile(configFile)
		if err != nil {
			log.Fatalf("failed to read config file: %v", err)
		}

		err = yaml.Unmarshal(configData, &config)
		if err != nil {
			log.Fatalf("failed to unmarshal config: %v", err)
		}
	} else {
		// Fallback to environment variables if the config file is not present
		config.KeyVaultURL = os.Getenv("KEYVAULT_URL")
		if config.KeyVaultURL == "" {
			log.Fatal("KEYVAULT_URL environment variable is not set")
		}

		// Get the SECRET_MAP environment variable and unmarshal it into the secretMap
		secretMapEnv := os.Getenv("SECRET_MAP")
		if secretMapEnv == "" {
			log.Fatal("SECRET_MAP environment variable is not set")
		}

		err := json.Unmarshal([]byte(secretMapEnv), &config.SecretMap)
		if err != nil {
			log.Fatalf("failed to unmarshal SECRET_MAP environment variable: %v", err)
		}
	}

	// Extract the Key Vault URL and secret map from the configuration
	keyVaultURL := config.KeyVaultURL
	secretMap := config.SecretMap

	// Authenticate with Azure using DefaultAzureCredential (Service Principal or Managed Identity)
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to get credential: %v", err)
	}

	// Create a new client for Key Vault
	client, err := azsecrets.NewClient(keyVaultURL, cred, nil)
	if err != nil {
		log.Fatalf("failed to create key vault client: %v", err)
	}

	// Create a map to hold the fetched secrets
	secrets := Secret{
		Secrets: make(map[string]string),
	}

	// Fetch secrets from Key Vault
	for secretName, yamlKey := range secretMap {
		secretResp, err := client.GetSecret(context.Background(), secretName, "", nil)
		if err != nil {
			log.Printf("failed to fetch secret %s: %v", secretName, err)
			continue
		}

		// Store the secret value in the map under the corresponding YAML key
		secrets.Secrets[yamlKey] = *secretResp.Value
	}

	// Convert the fetched secrets to YAML
	data, err := yaml.Marshal(&secrets)
	if err != nil {
		log.Fatalf("failed to marshal secrets to YAML: %v", err)
	}

	// Write YAML data to a file
	err = os.WriteFile("secrets.yaml", data, 0644)
	if err != nil {
		log.Fatalf("failed to write YAML to file: %v", err)
	}

	fmt.Println("Secrets have been written to secrets.yaml")
}
