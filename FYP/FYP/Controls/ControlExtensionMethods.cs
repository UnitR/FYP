using System;
using System.Collections.Generic;
using Windows.Foundation;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;

namespace FYP.Controls
{
    public static class ControlExtensionMethods
    {
        /// <summary>
        /// Extension method provided by Justin XL on StackOverflow: https://stackoverflow.com/a/32193216
        /// </summary>
        /// <param name="scrollViewer"></param>
        /// <param name="element"></param>
        /// <param name="isVerticalScrolling"></param>
        /// <param name="smoothScrolling"></param>
        /// <param name="zoomFactor"></param>
        public static void ScrollToElement(this ScrollViewer scrollViewer, UIElement element,
            bool isVerticalScrolling = true, bool smoothScrolling = true, float? zoomFactor = null)
        {
            var transform = element.TransformToVisual((UIElement)scrollViewer.Content);
            var position = transform.TransformPoint(new Point(0, 0));

            if (isVerticalScrolling)
            {
                scrollViewer.ChangeView(null, position.Y, zoomFactor, !smoothScrolling);
            }
            else
            {
                scrollViewer.ChangeView(position.X, null, zoomFactor, !smoothScrolling);
            }
        }
    }
}
