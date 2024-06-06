function toggleFields() {
    var versionField = document.getElementById("version");
    var externalizableIdCheckbox = document.getElementById("externalizableId");
    if (externalizableIdCheckbox){
        if (externalizableIdCheckbox.checked) {
            versionField.style.display = "none";
        } else {
            versionField.style.display = "block";
        }
    }
}
document.addEventListener("DOMContentLoaded", toggleFields());

(function() {
    // your page initialization code here
    // the DOM will be available here
    
    toggleFields();
})();

// Detect when your plugin is added as a post-build action
Behaviour.specify(".fs-third-party-uypload", 'my-plugin', 100, function (element) {
    // Trigger a custom event when your plugin's fields are loaded
    var externalizableIdCheckbox = document.getElementById("externalizableId");
    externalizableIdCheckbox.addEventListener("click", toggleFields);
});