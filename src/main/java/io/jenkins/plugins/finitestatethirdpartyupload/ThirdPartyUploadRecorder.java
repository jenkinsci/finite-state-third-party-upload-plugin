package io.jenkins.plugins.finitestatethirdpartyupload;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Publisher;
import hudson.tasks.Recorder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import io.jenkins.cli.shaded.org.apache.commons.lang.StringEscapeUtils;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.servlet.ServletException;
import jenkins.model.Jenkins;
import jline.internal.InputStreamReader;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

public class ThirdPartyUploadRecorder extends Recorder {

    private String finiteStateClientId;
    private String finiteStateSecret;
    private String finiteStateOrganizationContext;
    private String assetId;
    private String version;
    private Boolean externalizableId;
    private String filePath;
    private String testType;

    private String businessUnitId;
    private String createdByUserId;
    private String productId;
    private String artifactDescription;
    private String parsedVersion;

    @DataBoundConstructor
    public ThirdPartyUploadRecorder(
            String finiteStateClientId,
            String finiteStateSecret,
            String finiteStateOrganizationContext,
            String assetId,
            String version,
            Boolean externalizableId,
            String filePath,
            String testType,
            String businessUnitId,
            String createdByUserId,
            String productId,
            String artifactDescription,
            Boolean quickScan) {
        this.finiteStateClientId = finiteStateClientId;
        this.finiteStateSecret = finiteStateSecret;
        this.finiteStateOrganizationContext = finiteStateOrganizationContext;
        this.assetId = assetId;
        this.testType = testType;
        this.version = version;
        this.externalizableId = externalizableId;
        this.filePath = filePath;
        this.businessUnitId = businessUnitId;
        this.createdByUserId = createdByUserId;
        this.productId = productId;
        this.artifactDescription = artifactDescription;
    }

    public String getFiniteStateClientId() {
        return finiteStateClientId;
    }

    public String getFiniteStateSecret() {
        return finiteStateSecret;
    }

    public String getFiniteStateOrganizationContext() {
        return finiteStateOrganizationContext;
    }

    public String getAssetId() {
        return assetId;
    }

    public String getVersion() {
        return version;
    }

    public boolean getExternalizableId() {
        return externalizableId;
    }

    public String getFilePath() {
        return filePath;
    }

    public String getBusinessUnitId() {
        return businessUnitId;
    }

    public String getCreatedByUserId() {
        return createdByUserId;
    }

    public String getProductId() {
        return productId;
    }

    public String getArtifactDescription() {
        return artifactDescription;
    }

    public String getTestType() {
        return testType;
    }

    @DataBoundSetter
    public void setFiniteStateClientId(String finiteStateClientId) {
        this.finiteStateClientId = finiteStateClientId;
    }

    @DataBoundSetter
    public void setFiniteStateSecret(String finiteStateSecret) {
        this.finiteStateSecret = finiteStateSecret;
    }

    @DataBoundSetter
    public void setFiniteStateOrganizationContext(String finiteStateOrganizationContext) {
        this.finiteStateOrganizationContext = finiteStateOrganizationContext;
    }

    @DataBoundSetter
    public void setAssetId(String assetId) {
        this.assetId = assetId;
    }

    @DataBoundSetter
    public void setVersion(String version) {
        this.version = version;
    }

    @DataBoundSetter
    public void setExternalizableId(boolean externalizableId) {
        this.externalizableId = externalizableId;
    }

    @DataBoundSetter
    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    @DataBoundSetter
    public void setTestType(String testType) {
        this.testType = testType;
    }

    @DataBoundSetter
    public void setBusinessUnitId(String businessUnitId) {
        this.businessUnitId = businessUnitId;
    }

    @DataBoundSetter
    public void setCreatedByUserId(String createdByUserId) {
        this.createdByUserId = createdByUserId;
    }

    @DataBoundSetter
    public void setProductId(String productId) {
        this.productId = productId;
    }

    @DataBoundSetter
    public void setArtifactDescription(String artifactDescription) {
        this.artifactDescription = artifactDescription;
    }

    private File getFileFromWorkspace(AbstractBuild build, String relativeFilePath, BuildListener listener) {
        // Get the workspace directory for the current build
        FilePath workspace = build.getWorkspace();
        if (workspace != null) {
            String workspaceRemote = workspace.getRemote();
            // Construct the absolute path to the file
            // Return the file
            return new File(workspaceRemote, relativeFilePath);
        }
        return null;
    }

    /**
     * get secret values from form
     *
     * @param build
     * @param credentialId
     * @return
     */
    public String getSecretTextValue(AbstractBuild build, String credentialId) {
        // Retrieve the credentials by ID
        StandardCredentials credentials =
                CredentialsProvider.findCredentialById(credentialId, StringCredentials.class, build);

        // Check if the credential is of type StringCredentials
        if (credentials instanceof StringCredentials) {
            StringCredentials stringCredentials = (StringCredentials) credentials;
            // Get the secret value
            String secretValue = stringCredentials.getSecret().getPlainText();
            return secretValue;
        } else {
            return null;
        }
    }

    public static String escapeEnvVar(String input) {
        return StringEscapeUtils.escapeJava(input);
    }

    public static String validateEnvVar(String input) {
        if (input == null || input.isEmpty()) {
            throw new IllegalArgumentException("Environment variable value cannot be null or empty");
        }
        if (!input.matches("^[a-zA-Z0-9-_]+$")) {
            throw new IllegalArgumentException("Environment variable value contains invalid characters: " + input);
        }
        return input;
    }

    public static boolean isDockerInstalled() {
        ProcessBuilder processBuilder = new ProcessBuilder("docker", "--version");
        try {
            Process process = processBuilder.start();
            int exitCode = process.waitFor();
            return exitCode == 0;
        } catch (IOException | InterruptedException e) {
            // Log the exception instead of printing the stack trace
            e.printStackTrace();
        }
        return false;
    }

    private boolean buildDockerImage(File dockerDir, BuildListener listener) {
        ProcessBuilder buildProcessBuilder =
                new ProcessBuilder("docker", "build", "-t", "finite-state-upload", dockerDir.getAbsolutePath());
        buildProcessBuilder.redirectErrorStream(true);
        try {
            Process buildProcess = buildProcessBuilder.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(buildProcess.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    listener.getLogger().println(line);
                }
            }
            int buildExitCode = buildProcess.waitFor();
            if (buildExitCode != 0) {
                listener.getLogger().println("Docker build failed");
                return false;
            }
        } catch (IOException | InterruptedException e) {
            // Log the exception instead of printing the stack trace
            e.printStackTrace();
            listener.getLogger().println("Docker build process encountered an error: " + e.getMessage());
            return false;
        }
        return true;
    }

    @Override
    public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener)
            throws InterruptedException, IOException {
        if (isDockerInstalled()) {
            listener.getLogger().println("Docker is installed");
        } else {
            listener.getLogger().println("Docker is not installed");
            return false;
        }

        String parsedVersion = getExternalizableId() ? build.getExternalizableId() : version;
        String parsedFiniteStateClientId = validateEnvVar(getSecretTextValue(build, finiteStateClientId));
        String parsedFiniteStateSecret = validateEnvVar(getSecretTextValue(build, finiteStateSecret));
        String parsedFiniteStateOrganizationContext =
                validateEnvVar(getSecretTextValue(build, finiteStateOrganizationContext));

        List<String> envList = new ArrayList<>();
        envList.add("INPUT_FINITE-STATE-CLIENT-ID=" + escapeEnvVar(parsedFiniteStateClientId));
        envList.add("INPUT_FINITE-STATE-SECRET=" + escapeEnvVar(parsedFiniteStateSecret));
        envList.add("INPUT_FINITE-STATE-ORGANIZATION-CONTEXT=" + escapeEnvVar(parsedFiniteStateOrganizationContext));
        envList.add("INPUT_ASSET-ID=" + escapeEnvVar(assetId));
        envList.add("INPUT_VERSION=" + escapeEnvVar(parsedVersion));
        envList.add("INPUT_TEST-TYPE=" + escapeEnvVar(testType));
        envList.add("INPUT_BUSINESS-UNIT-ID=" + escapeEnvVar(businessUnitId));
        envList.add("INPUT_CREATED-BY-USER-ID=" + escapeEnvVar(createdByUserId));
        envList.add("INPUT_PRODUCT-ID=" + escapeEnvVar(productId));
        envList.add("INPUT_ARTIFACT-DESCRIPTION=" + escapeEnvVar(artifactDescription));

        URL resourceUrl = ThirdPartyUploadRecorder.class
                .getClassLoader()
                .getResource("io/jenkins/plugins/finitestatethirdpartyupload/docker/Dockerfile");

        if (resourceUrl == null) {
            listener.getLogger().println("Dockerfile not found");
            return false;
        }
        File dockerfile = new File(resourceUrl.getFile());
        File dockerDir = dockerfile.getParentFile();

        if (!buildDockerImage(dockerDir, listener)) {
            return false;
        }

        buildDockerImage(dockerDir, listener);

        // Step 2: Verify the file exists
        File file = getFileFromWorkspace(build, filePath, listener);
        if (file == null || !file.exists()) {
            listener.getLogger().println("File specified in file path not found: " + filePath);
            return false;
        } else {
            listener.getLogger().println("Found file: " + file.getAbsolutePath());
        }
        envList.add("INPUT_FILE-PATH=/tmp/" + file.getName()); // set env filename

        String hostDirectory = file.getParent();
        String containerDirectoryPath = "/tmp/";

        // Step 3: Run the Docker container
        List<String> runCommand = new ArrayList<>();
        runCommand.add("docker");
        runCommand.add("run");
        runCommand.add("--rm");
        for (String envVar : envList) {
            runCommand.add("-e");
            runCommand.add(envVar);
        }
        runCommand.add("-v");
        runCommand.add(hostDirectory + ":" + containerDirectoryPath);
        runCommand.add("finite-state-upload");

        ProcessBuilder runProcessBuilder = new ProcessBuilder(runCommand);
        runProcessBuilder.redirectErrorStream(true);
        Process runProcess = runProcessBuilder.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(runProcess.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                listener.getLogger().println(line);
            }
        }

        int runExitCode = runProcess.waitFor();
        if (runExitCode != 0) {
            listener.getLogger().println("Docker run failed");
            return false;
        }
        build.addAction(new ThirdPartyUploadAction(assetId));
        // dockerClient.close();
        return true;
    }

    @Symbol("fs-third-party-upload")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {

        @RequirePOST
        public ListBoxModel doFillFiniteStateClientIdItems(
                @AncestorInPath Item item, @QueryParameter String finiteStateClientId) {
            StandardListBoxModel items = new StandardListBoxModel();
            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return items.includeCurrentValue(finiteStateClientId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return items.includeCurrentValue(finiteStateClientId);
                }
            }
            for (StandardCredentials credential : CredentialsProvider.lookupCredentials(
                    StandardCredentials.class, (Item) null, ACL.SYSTEM, Collections.emptyList())) {
                items.add(credential.getId());
            }
            return items;
        }

        @RequirePOST
        public ListBoxModel doFillFiniteStateSecretItems(
                @AncestorInPath Item item, @QueryParameter String finiteStateSecret) {
            StandardListBoxModel items = new StandardListBoxModel();
            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return items.includeCurrentValue(finiteStateSecret);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return items.includeCurrentValue(finiteStateSecret);
                }
            }
            for (StandardCredentials credential : CredentialsProvider.lookupCredentials(
                    StandardCredentials.class, (Item) null, ACL.SYSTEM, Collections.emptyList())) {
                items.add(credential.getId());
            }
            return items;
        }

        @RequirePOST
        public ListBoxModel doFillFiniteStateOrganizationContextItems(
                @AncestorInPath Item item, @QueryParameter String finiteStateOrganizationContext) {
            StandardListBoxModel items = new StandardListBoxModel();
            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return items.includeCurrentValue(finiteStateOrganizationContext);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                    return items.includeCurrentValue(finiteStateOrganizationContext);
                }
            }
            for (StandardCredentials credential : CredentialsProvider.lookupCredentials(
                    StandardCredentials.class, (Item) null, ACL.SYSTEM, Collections.emptyList())) {
                items.add(credential.getId());
            }
            return items;
        }

        private FormValidation checkRequiredValue(Item item, String value) {
            if (item == null
                    || !item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                return FormValidation.error("You do not have permission to perform this action.");
            }
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error("This value is required");
            }
            return FormValidation.ok();
        }

        @RequirePOST
        // lgtm[jenkins/no-permission-check]
        public FormValidation doCheckFiniteStateClientId(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @RequirePOST
        // lgtm[jenkins/no-permission-check]
        public FormValidation doCheckFiniteStateSecret(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @RequirePOST
        // lgtm[jenkins/no-permission-check]
        public FormValidation doCheckFiniteStateOrganizationContext(
                @AncestorInPath Item item, @QueryParameter String value) throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @RequirePOST
        // lgtm[jenkins/no-permission-check]
        public FormValidation doCheckAssetId(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @RequirePOST
        // lgtm[jenkins/no-permission-check]
        public FormValidation doCheckVersion(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @RequirePOST
        // lgtm[jenkins/no-permission-check]
        public FormValidation doCheckFilePath(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(item, value);
        }

        @RequirePOST
        public FormValidation doCheckTestType(@AncestorInPath Item item, @QueryParameter String value)
                throws IOException, ServletException {
            if (item == null
                    || (!item.hasPermission(Item.EXTENDED_READ) && !item.hasPermission(CredentialsProvider.USE_ITEM))) {
                return FormValidation.error("You do not have permission to perform this action.");
            }
            if (value == null || value.trim().isEmpty() || ("-- Select --".equals(value))) {
                return FormValidation.error("This value is required. Please, select a valid option");
            }
            return FormValidation.ok();
        }

        @RequirePOST
        @SuppressWarnings("lgtm[jenkins/no-permission-check]")
        public ListBoxModel doFillTestTypeItems() {
            ListBoxModel items = new ListBoxModel();
            String[] testTypes = {
                "-- Select --",
                "acunetix360_scan",
                "acunetix_scan",
                "anchore_engine_scan",
                "anchore_enterprise_policy_check",
                "anchore_grype",
                "anchorectl_policies_report",
                "anchorectl_vuln_report",
                "appspider_scan",
                "aqua_scan",
                "arachni_scan",
                "auditjs_scan",
                "aws_prowler_scan",
                "aws_prowler_v3",
                "aws_scout2_scan",
                "aws_security_finding_format_asff_scan",
                "aws_security_hub_scan",
                "azure_security_center_recommendations_scan",
                "bandit_scan",
                "blackduck_api",
                "blackduck_component_risk",
                "blackduck_hub_scan",
                "brakeman_scan",
                "bugcrowd_api_import",
                "bugcrowd_scan",
                "bundler_audit_scan",
                "burp_enterprise_scan",
                "burp_graphql_api",
                "burp_rest_api",
                "burp_scan",
                "cargoaudit_scan",
                "checkmarx_osa",
                "checkmarx_scan",
                "checkmarx_scan_detailed",
                "checkov_scan",
                "clair_klar_scan",
                "clair_scan",
                "cloudsploit_scan",
                "cobalt_io_api_import",
                "cobalt_io_scan",
                "codechecker_report_native",
                "contrast_scan",
                "coverity_api",
                "crashtest_security_json_file",
                "crashtest_security_xml_file",
                "credscan_scan",
                "cyclonedx",
                "dawnscanner_scan",
                "dependency_check_scan",
                "dependency_track_finding_packaging_format_fpf_export",
                "detect_secrets_scan",
                "docker_bench_security_scan",
                "dockle_scan",
                "drheader_json_importer",
                "dsop_scan",
                "edgescan_scan",
                "eslint_scan",
                "fortify_scan",
                "generic_findings_import",
                "ggshield_scan",
                "github_vulnerability_scan",
                "gitlab_api_fuzzing_report_scan",
                "gitlab_container_scan",
                "gitlab_dast_report",
                "gitlab_dependency_scanning_report",
                "gitlab_sast_report",
                "gitlab_secret_detection_report",
                "gitleaks_scan",
                "gosec_scanner",
                "govulncheck_scanner",
                "hackerone_cases",
                "hadolint_dockerfile_check",
                "harbor_vulnerability_scan",
                "horusec_scan",
                "huskyci_report",
                "hydra_scan",
                "ibm_appscan_dast",
                "immuniweb_scan",
                "intsights_report",
                "jfrog_xray_api_summary_artifact_scan",
                "jfrog_xray_scan",
                "jfrog_xray_unified_scan",
                "kics_scan",
                "kiuwan_scan",
                "kube_bench_scan",
                "logic_bomb_scan",
                "meterian_scan",
                "microfocus_webinspect_scan",
                "mobsf_scan",
                "mobsfscan_scan",
                "mozilla_observatory_scan",
                "netsparker_scan",
                "neuvector_compliance",
                "neuvector_rest",
                "nexpose_scan",
                "nikto_scan",
                "nmap_scan",
                "node_security_platform_scan",
                "npm_audit_scan",
                "nuclei_scan",
                "openscap_vulnerability_scan",
                "openvas_csv",
                "ort_evaluated_model_importer",
                "ossindex_devaudit_sca_scan_importer",
                "outpost24_scan",
                "php_security_audit_v2",
                "php_symfony_security_check",
                "pip_audit_scan",
                "pmd_scan",
                "popeye_scan",
                "pwn_sast",
                "qualys_infrastructure_scan_webgui_xml",
                "qualys_scan",
                "qualys_webapp_scan",
                "retire_js_scan",
                "rubocop_scan",
                "rusty_hog_scan",
                "sarif",
                "scantist_scan",
                "scout_suite_scan",
                "semgrep_json_report",
                "skf_scan",
                "snyk_scan",
                "solar_appscreener_scan",
                "sonarqube_scan",
                "sonarqube_scan_detailed",
                "sonatype_application_scan",
                "spdx",
                "spotbugs_scan",
                "ssl_labs_scan",
                "sslscan",
                "sslyze_scan",
                "sslyze_scan_json",
                "stackhawk_hawkscan",
                "talisman_scan",
                "tenable_scan",
                "terrascan_scan",
                "testssl_scan",
                "tfsec_scan",
                "trivy_operator_scan",
                "trivy_scan",
                "trufflehog3_scan",
                "trufflehog_scan",
                "trustwave_fusion_api_scan",
                "trustwave_scan_csv",
                "twistlock_image_scan",
                "vcg_scan",
                "veracode_scan",
                "veracode_sourceclear_scan",
                "vulners",
                "wapiti_scan",
                "wazuh",
                "wfuzz_json_report",
                "whispers_scan",
                "whitehat_sentinel",
                "whitesource_scan",
                "wpscan",
                "xanitizer_scan",
                "yarn_audit_scan",
                "zap_scan"
            };

            for (String type : testTypes) {
                items.add(type, type);
            }
            return items;
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Finite State - Third Party Upload";
        }
    }
}
