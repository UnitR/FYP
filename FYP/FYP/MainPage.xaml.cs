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
        private readonly StorageHandler _storageHandler;

        private StorageHandler.FileAction _currAction;
        IStorageFile _currActiveFile = null;

        private ObservableCollection<FileNameMapping> _fileMappings = new ObservableCollection<FileNameMapping>();

        internal ObservableCollection<FileNameMapping> FileMappings => this._fileMappings;

        public MainPage()
        {
            this.InitializeComponent();
            this.Unloaded += (sender, args) =>
            {
                _storageHandler.Dispose();
            };

            _storageHandler = new StorageHandler();
            _storageHandler.Initialise();

            FileSelectGrid.Visibility = Visibility.Collapsed;
            ConfirmPanel.Visibility = Visibility.Collapsed;
        }

        private void BtnSecureFile_Click(object sender, RoutedEventArgs e)
        {
            _currAction = StorageHandler.FileAction.Encrypt;

            BtnFilePick.Visibility = Visibility.Visible;
            ProtectedFileList.Visibility = Visibility.Collapsed;
            FileSelectGrid.Visibility = Visibility.Visible;

            MainScroller.ScrollToElement(
                element: FileSelectGrid,
                isVerticalScrolling: false);
        }

        private void BtnViewFile_Click(object sender, RoutedEventArgs e)
        {
            _currAction = StorageHandler.FileAction.Decrypt;

            if (FileMappings.Count == 0)
            {
                foreach (FileNameMapping mapping in _storageHandler.FileList.FileMappings)
                {
                    FileMappings.Add(mapping);
                }
            }

            BtnFilePick.Visibility = Visibility.Collapsed;
            ProtectedFileList.Visibility = Visibility.Visible;
            FileSelectGrid.Visibility = Visibility.Visible;

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

            ConfirmPanel.Visibility = Visibility.Visible;

            // Scroll view to next step
            MainScroller.ScrollToElement(
                element: ConfirmPanel,
                isVerticalScrolling: false);
        }

        private async void BtnConfirm_OnClick(object sender, RoutedEventArgs e)
        {
            switch (_currAction)
            {
                case StorageHandler.FileAction.Encrypt:
                {
                    await EncryptFileAsync();
                    // Update the master file after each encryption
                    var file = await _storageHandler.UpdateMasterListFileAsync(_currActiveFile.Name);
                    FileMappings.Add(
                        new FileNameMapping(_currActiveFile.Name,
                        file.Name));
                    break;
                }
                case StorageHandler.FileAction.Decrypt:
                    {
                        IStorageFile file = await DecryptFileAsync();
                        await Windows.System.Launcher.LaunchFileAsync(file);
                        break;
                    }
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        private async Task<bool> EncryptFileAsync()
        {
            var fileStream = await _currActiveFile.OpenStreamForReadAsync();
            var fileBytes = new byte[(int)fileStream.Length];
            await fileStream.ReadAsync(fileBytes, 0, (int)fileStream.Length);

            try
            {
                // Encrypt stream
                FileEncryptionData fed = _storageHandler.EncryptFile(fileBytes);
                // Save to disk
                await _storageHandler.SaveObjectToJsonAsync("testRun.enc", fed);
            }
            catch (Exception ex)
            {
                return false;
            }

            return true;
        }

        private async Task<IStorageFile> DecryptFileAsync()
        {
            const string fileName = "testRun.enc";
            const string fileExt = "pdf";

            string fedJson = await _storageHandler.ReadFileAsync(fileName);
            if (String.IsNullOrWhiteSpace(fedJson))
            {
                throw new ArgumentNullException(nameof(fileName), "Cannot open non-existent file.");
            }

            FileEncryptionData fed = JsonConvert.DeserializeObject<FileEncryptionData>(fedJson);

            // Get the decrypted file
            byte[] fileBytes = await _storageHandler.DecryptFileAsync(fed);

            // Save the file temporarily

            return await _storageHandler.SaveFileBytesTempAsync(
                new FileData(fileName, fileExt, fileBytes));
        }

        private async void ProtectedFileList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            FileNameMapping selected = ProtectedFileList.SelectedItem as FileNameMapping;
            _currActiveFile = await _storageHandler.LoadFileAsync(selected?.SecureName);

            if (_currActiveFile == null) return; 
                
            ConfirmPanel.Visibility = Visibility.Visible;
            MainScroller.ScrollToElement(
                element: ConfirmPanel,
                isVerticalScrolling: false);
        }
    }
}
