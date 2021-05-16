﻿using System;
using System.IO;
using System.Threading.Tasks;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.Storage;
using FYP.Controls;
using FYP.Data;
using Newtonsoft.Json;
using TpmStorageHandler.Structures;

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

        public MainPage()
        {
            this.InitializeComponent();
            this.Unloaded += (sender, args) =>
            {
                _storageHandler.Dispose();
            };

            _storageHandler = new StorageHandler();
            _storageHandler.Initialise();
        }

        private void BtnSecureFile_Click(object sender, RoutedEventArgs e)
        {
            _currAction = StorageHandler.FileAction.Encrypt;
            BtnFilePick.Visibility = Visibility.Visible;
            ProtectedFileList.Visibility = Visibility.Collapsed;
            MainScroller.ScrollToElement(
                element: FileSelectGrid, 
                isVerticalScrolling: false);
        }

        private void BtnViewFile_Click(object sender, RoutedEventArgs e)
        {
            _currAction = StorageHandler.FileAction.Decrypt;
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

            // Display file information
            LblFilePath.Text = _currActiveFile.Path;
            LblFileName.Text = _currActiveFile.Name;

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
                    await EncryptFileAsync();
                    break;
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

            string fedJson = await _storageHandler.LoadFileAsync(fileName);
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
    }
}
