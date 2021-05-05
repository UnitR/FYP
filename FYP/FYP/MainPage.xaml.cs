using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Windows.Storage;

// The Blank Page item template is documented at https://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace FYP
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {

        IStorageFile _currActiveFile = null;

        public MainPage()
        {
            this.InitializeComponent();
        }

        private void BtnSecureFile_Click(object sender, RoutedEventArgs e)
        {
            HubMain.ScrollToSection(HubMain.Sections[1]);
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

            // Scroll view to next step
            HubMain.ScrollToSection(HubMain.Sections[2]);
        }


    }
}
