package com.finitestate.thirdpartyupload;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.command.BuildImageCmd;
import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.dockerjava.api.command.LogContainerCmd;
import com.github.dockerjava.api.command.WaitContainerResultCallback;
import com.github.dockerjava.api.model.Bind;
import com.github.dockerjava.api.model.Frame;
import com.github.dockerjava.api.model.Volume;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientBuilder;
import com.github.dockerjava.core.command.BuildImageResultCallback;
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
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.servlet.ServletException;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

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

    @Override
    public boolean perform(AbstractBuild build, Launcher launcher, BuildListener listener)
            throws InterruptedException, IOException {

        if (getExternalizableId()) {
            parsedVersion = build.getExternalizableId();
        } else {
            parsedVersion = version;
        }
        String parsedFiniteStateClientId = getSecretTextValue(build, finiteStateClientId);
        String parsedFiniteStateSecret = getSecretTextValue(build, finiteStateSecret);
        String parsedFiniteStateOrganizationContext = getSecretTextValue(build, finiteStateOrganizationContext);

        // Create a map to hold environment variables
        List<String> envList = new ArrayList<>();
        envList.add("INPUT_FINITE-STATE-CLIENT-ID=" + parsedFiniteStateClientId);
        envList.add("INPUT_FINITE-STATE-SECRET=" + parsedFiniteStateSecret);
        envList.add("INPUT_FINITE-STATE-ORGANIZATION-CONTEXT=" + parsedFiniteStateOrganizationContext);
        envList.add("INPUT_ASSET-ID=" + assetId);
        envList.add("INPUT_VERSION=" + parsedVersion);
        envList.add("INPUT_TEST-TYPE=" + testType);
        
        // non required parameters:
        envList.add("INPUT_BUSINESS-UNIT-ID=" + businessUnitId);
        envList.add("INPUT_CREATED-BY-USER-ID=" + createdByUserId);
        envList.add("INPUT_PRODUCT-ID=" + productId);
        envList.add("INPUT_ARTIFACT-DESCRIPTION=" + artifactDescription);

        // Docker client configuration
        DefaultDockerClientConfig config =
                DefaultDockerClientConfig.createDefaultConfigBuilder().build();
        DockerClient dockerClient = DockerClientBuilder.getInstance(config).build();

        URL resourceUrl =
                ThirdPartyUploadRecorder.class.getClassLoader().getResource("com/finitestate/docker/Dockerfile");

        BuildImageCmd buildImageCmd = dockerClient.buildImageCmd();

        // Step 2: Set the Dockerfile
        buildImageCmd.withDockerfile(new File(resourceUrl.getFile()));

        // Step 3: Execute the build and get the result callback
        BuildImageResultCallback resultCallback = new BuildImageResultCallback() {
            @Override
            public void onNext(com.github.dockerjava.api.model.BuildResponseItem item) {
                // Handle build response
                System.out.println(item.getStream());
                super.onNext(item);
            }

            @Override
            public void onError(Throwable throwable) {
                super.onError(throwable);
            }
        };

        buildImageCmd.exec(resultCallback);

        // Step 4: Await the image ID
        String imageId = resultCallback.awaitImageId();

        System.out.println("Built image ID: " + imageId);
        listener.getLogger().println("imageId: " + imageId);

        File file = getFileFromWorkspace(build, filePath, listener);
        if (file == null || !file.exists()) {
            // File not found
            listener.getLogger().println("File specified in file path not found: " + filePath);
            return false;
        } else {
            // Process the file
            listener.getLogger().println("Found file: " + file.getAbsolutePath());
        }
        envList.add("INPUT_FILE-PATH=/tmp/" + file.getName()); // set env filename

        // Create a list to hold volume mappings
        // String hostFilePath = file.getAbsolutePath();
        String hostDirectory = file.getParent();
        String containerDirectoryPath = "/tmp/";

        Bind volumeBind = new Bind(hostDirectory, new Volume(containerDirectoryPath));
        // Create a Volume object for the mapping

        // Run Docker container from the built image
        CreateContainerCmd createContainerCmd =
                dockerClient.createContainerCmd(imageId).withBinds(volumeBind).withEnv(envList);
        String containerId = createContainerCmd.exec().getId();
        dockerClient.startContainerCmd(containerId).exec();

        // Retrieve and log container logs
        LogContainerCmd logContainerCmd = dockerClient
                .logContainerCmd(containerId)
                .withStdErr(true)
                .withStdOut(true)
                .withFollowStream(true)
                .withTailAll();

        // Retrieve and log container logs
        ResultCallback.Adapter<Frame> callback = new ResultCallback.Adapter<Frame>() {
            @Override
            public void onNext(Frame frame) {
                listener.getLogger().println(frame.toString());
            }
        };
        logContainerCmd.exec(callback).awaitCompletion();

        // Wait for the container to finish
        dockerClient
                .waitContainerCmd(containerId)
                .exec(new WaitContainerResultCallback())
                .awaitCompletion(5, TimeUnit.MINUTES);

        build.addAction(new ThirdPartyUploadAction(assetId));
        // dockerClient.close();
        return true;
    }

    @Symbol("greet")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Publisher> {
        public ListBoxModel doFillFiniteStateClientIdItems(
                @AncestorInPath Item item, @QueryParameter String finiteStateClientId) {
            ListBoxModel items = new ListBoxModel();
            for (StandardCredentials credential : CredentialsProvider.lookupCredentials(
                    StandardCredentials.class, (Item) null, ACL.SYSTEM, Collections.emptyList())) {
                items.add(credential.getId());
            }
            return items;
        }

        public ListBoxModel doFillFiniteStateSecretItems(
                @AncestorInPath Item item, @QueryParameter String finiteStateSecret) {
            ListBoxModel items = new ListBoxModel();
            for (StandardCredentials credential : CredentialsProvider.lookupCredentials(
                    StandardCredentials.class, (Item) null, ACL.SYSTEM, Collections.emptyList())) {
                items.add(credential.getId());
            }
            return items;
        }

        public ListBoxModel doFillFiniteStateOrganizationContextItems(
                @AncestorInPath Item item, @QueryParameter String finiteStateOrganizationContext) {
            ListBoxModel items = new ListBoxModel();
            for (StandardCredentials credential : CredentialsProvider.lookupCredentials(
                    StandardCredentials.class, (Item) null, ACL.SYSTEM, Collections.emptyList())) {
                items.add(credential.getId());
            }
            return items;
        }

        private FormValidation checkRequiredValue(String value) {
            if (value.length() == 0) {
                return FormValidation.error("This value is required");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckFiniteStateClientId(@QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(value);
        }

        public FormValidation doCheckFiniteStateSecret(@QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(value);
        }

        public FormValidation doCheckFiniteStateOrganizationContext(@QueryParameter String value)
                throws IOException, ServletException {
            return checkRequiredValue(value);
        }

        public FormValidation doCheckAssetId(@QueryParameter String value) throws IOException, ServletException {
            return checkRequiredValue(value);
        }

        public FormValidation doCheckVersion(@QueryParameter String value) throws IOException, ServletException {
            return checkRequiredValue(value);
        }

        public FormValidation doCheckFilePath(@QueryParameter String value) throws IOException, ServletException {
            return checkRequiredValue(value);
        }
        
        public FormValidation doCheckTestType(@QueryParameter String value) throws IOException, ServletException {
            return checkRequiredValue(value);
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
