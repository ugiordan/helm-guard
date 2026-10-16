// Diagram zoom: click to enlarge images in docs
document.addEventListener('DOMContentLoaded', function() {
  var images = document.querySelectorAll('.md-content img');
  images.forEach(function(img) {
    img.style.cursor = 'zoom-in';
    img.addEventListener('click', function() {
      if (this.classList.contains('zoomed')) {
        this.classList.remove('zoomed');
        this.style.maxWidth = '';
        this.style.cursor = 'zoom-in';
      } else {
        this.classList.add('zoomed');
        this.style.maxWidth = '100%';
        this.style.cursor = 'zoom-out';
      }
    });
  });
});
