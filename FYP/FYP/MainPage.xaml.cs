using FYP.Controls;
using FYP.Data;
using Newtonsoft.Json;
using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using TpmStorageHandler.Structures;
using Windows.Storage;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;

// The Blank Page item template is documented at https://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace FYP
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        /// <summary>
        /// Controls all file-specific operations along with encryption and decryption.
        /// </summary>
        private readonly StorageHandler _storageHandler;

        /// <summary>
        /// Represents the currently selected user action, i.e. Encryption or Decryption of a file.
        /// </summary>
        private StorageHandler.FileAction _currAction;

        /// <summary>
        /// Holds a reference to the currently selected file for encryption and decryption.
        /// </summary>
        private IStorageFile _currActiveFile;

        /// <summary>
        /// Holds the mapping corresponding to the currently selected file to Decrypt and its
        /// secure name representation on disk.
        /// </summary>
        private FileNameMapping _currFileMapping;

        /// <summary>
        /// Source for the list of protected files.
        /// </summary>
        private ObservableCollection<FileNameMapping> _fileMappings = new ObservableCollection<FileNameMapping>();

        /// <summary>
        /// Accessible property for the list of protected files.
        /// </summary>
        internal ObservableCollection<FileNameMapping> FileMappings => this._fileMappings;

        public MainPage()
        {
            this.InitializeComponent();

            // Initialise storage handler
            _storageHandler = new StorageHandler();

#pragma warning disable CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
            // Initialise the storage handler.
            // TODO: This is a race condition and poorly designed. Needs reworking.
            _storageHandler.Initialise();
#pragma warning restore CS4014

            // Hide anything which is not in Step 1. Progressive enabling.
            FileSelectGrid.Visibility = Visibility.Collapsed;
            ConfirmGrid.Visibility = Visibility.Collapsed;
        }

        private void BtnSecureFile_Click(object sender, RoutedEventArgs e)
        {
            _currAction = StorageHandler.FileAction.Encrypt;

            // Set visibility of relevant items
            BtnFilePick.Visibility = Visibility.Visible;
            ProtectedFileList.Visibility = Visibility.Collapsed;
            FileSelectGrid.Visibility = Visibility.Visible;

            // Ensure the next step is in view
            MainScroller.ScrollToElement(
                element: FileSelectGrid,
                isVerticalScrolling: false);
        }

        private void BtnViewFile_Click(object sender, RoutedEventArgs e)
        {
            _currAction = StorageHandler.FileAction.Decrypt;

            // Initialise the list of protected files before displaying the
            // related ListView
            if (FileMappings.Count == 0)
            {
                foreach (FileNameMapping mapping in _storageHandler.FileList.FileMappings)
                {
                    FileMappings.Add(mapping);
                }
            }

            // Set visibility of relevant items
            BtnFilePick.Visibility = Visibility.Collapsed;
            ProtectedFileList.Visibility = Visibility.Visible;
            FileSelectGrid.Visibility = Visibility.Visible;

            // Ensure the next step is in view
            MainScroller.ScrollToElement(
                element: FileSelectGrid,
                isVerticalScrolling: false);
        }

        private async void BtnFilePick_Click(object sender, RoutedEventArgs e)
        {
            // Pick file
            var picker = new Windows.Storage.Pickers.FileOpenPicker();
            picker.ViewMode = Windows.Storage.Pickers.PickerViewMode.Thumbnail;
            picker.SuggestedStartLocation = Windows.Storage.Pickers.PickerLocationId.DocumentsLibrary;
            picker.FileTypeFilter.Add("*");

            // Cache file in memory
            _currActiveFile = await picker.PickSingleFileAsync();

            // The file is null: the user most likely didn't pick one
            if (_currActiveFile == null)
                return;

            // Display file information
            LblFilePath.Text = _currActiveFile.Path;
            LblFileName.Text = _currActiveFile.Name;

            ConfirmGrid.Visibility = Visibility.Visible;

            // Scroll view to next step
            MainScroller.ScrollToElement(
                element: ConfirmGrid,
                isVerticalScrolling: false);
        }

        private async void BtnConfirm_OnClick(object sender, RoutedEventArgs e)
        {
            // Used for the success message; ensures to show the user a relevant message.
            string operation;

            switch (_currAction)
            {
                case StorageHandler.FileAction.Encrypt:
                {
                    // Update the master for each encryption
                    // TODO: If encryption fails, this would need to either remove the element or even better, only add the element after the encryption succeeds.
                    string secureFileName = await _storageHandler.UpdateMasterListFileAsync(_currActiveFile.Name);
                    FileMappings.Add(
                        new FileNameMapping(
                            _currActiveFile.Name,
                            secureFileName));
                    // Encrypt file
                    await EncryptFileAsync(secureFileName);
                    operation = "is now protected";
                    break;
                }
                case StorageHandler.FileAction.Decrypt:
                    {
                        // Decrypt file
                        IStorageFile file = await DecryptFileAsync();
                        // Open file with default system viewer
                        await Windows.System.Launcher.LaunchFileAsync(file);
                        operation = "should open shortly";
                        break;
                    }
                default:
                    throw new ArgumentOutOfRangeException();
            }

            // Display success message
            ContentDialog dialog = new ContentDialog
            {
                Title = "All done!",
                Content = $"Your file {operation}.",
                CloseButtonText = "OK"
            };
            dialog.ShowAsync();

            // Clean up
            _currActiveFile = null;
            _currFileMapping = null;
            LblFileName.Text = String.Empty;
            LblFilePath.Text = String.Empty;
            ConfirmGrid.Visibility = Visibility.Collapsed;
            FileSelectGrid.Visibility = Visibility.Collapsed;
        }

        /// <summary>
        /// Encrypts the currently active file.
        /// </summary>
        /// <param name="resultFileName">
        /// The name of the file to write the encrypted file object to.
        /// </param>
        /// <returns>
        /// True if the operation succeeds, false otherwise.
        /// </returns>
        private async Task<bool> EncryptFileAsync(string resultFileName)
        {
            // Get the file bytes to encrypt.
            var fileStream = await _currActiveFile.OpenStreamForReadAsync();
            var fileBytes = new byte[(int)fileStream.Length];
            await fileStream.ReadAsync(fileBytes, 0, (int)fileStream.Length);

            try
            {
                // Encrypt stream
                FileEncryptionData fed = _storageHandler.EncryptFile(fileBytes);
                // Save to disk
                await _storageHandler.SaveObjectToJsonAsync(resultFileName, fed);
            }
            catch (Exception ex)
            {
                // Indicate that the operation failed.
                return false;
            }

            // Success
            return true;
        }

        /// <summary>
        /// Decrypts the currently chosen file.
        /// </summary>
        /// <returns>
        /// A handle to the decrypted file (usually TEMP.*)
        /// </returns>
        private async Task<IStorageFile> DecryptFileAsync()
        {
            // Retrieve the protected file and convert it to a useful object
            string fedJson = await _storageHandler.ReadFileAsync(_currFileMapping.SecureName);
            if (String.IsNullOrWhiteSpace(fedJson))
            {
                throw new ArgumentNullException(
                    nameof(_currFileMapping.SecureName),
                    "Cannot open non-existent file.");
            }
            FileEncryptionData fed = JsonConvert.DeserializeObject<FileEncryptionData>(fedJson);

            // Get the decrypted file
            byte[] fileBytes = await _storageHandler.DecryptFileAsync(fed);

            // Save the file temporarily

            return await _storageHandler.SaveFileBytesTempAsync(
                new FileData(
                    _currFileMapping.SecureName,
                    _currFileMapping.FileExt,
                    fileBytes)
                );
        }

        private async void ProtectedFileList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _currFileMapping = ProtectedFileList.SelectedItem as FileNameMapping;
            _currActiveFile = await _storageHandler.LoadFileAsync(_currFileMapping.SecureName);

            if (_currActiveFile == null) return;

            LblFileName.Text = _currFileMapping.OriginalName;
            LblFilePath.Text = "N/A";
                
            ConfirmGrid.Visibility = Visibility.Visible;
            MainScroller.ScrollToElement(
                element: ConfirmGrid,
                isVerticalScrolling: false);
        }
    }
}
