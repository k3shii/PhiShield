document.addEventListener('DOMContentLoaded', function() {
    loadBookmarks();
});

async function loadBookmarks() {
    try {
        const response = await fetch('http://127.0.0.1:5000/whitelist');
        if (!response.ok) {
            throw new Error('Failed to load bookmarks');
        }
        const bookmarks = await response.json();
        
        const container = document.getElementById('bookmarkContainer');
        container.innerHTML = '';
        
        if (bookmarks.length === 0) {
            container.innerHTML = '<div class="empty-message">No bookmarked URLs</div>';
            return;
        }
        
        bookmarks.forEach(entry => {
            const item = document.createElement('div');
            item.className = 'bookmark-item';
            
            const urlText = document.createElement('div');
            urlText.className = 'bookmark-url';
            urlText.textContent = entry.url;
            
            const removeButton = document.createElement('button');
            removeButton.className = 'remove-button';
            removeButton.textContent = '×';
            removeButton.onclick = () => removeBookmark(entry.url);
            
            item.appendChild(urlText);
            item.appendChild(removeButton);
            container.appendChild(item);
        });
    } catch (error) {
        console.error('Error loading bookmarks:', error);
        const container = document.getElementById('bookmarkContainer');
        container.innerHTML = '<div class="empty-message">Error loading bookmarks</div>';
    }
}

async function removeBookmark(url) {
    try {
        const response = await fetch('http://127.0.0.1:5000/whitelist', {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });
        
        if (!response.ok) {
            throw new Error('Failed to remove bookmark');
        }
        
        // Reload the bookmarks list
        await loadBookmarks();
    } catch (error) {
        console.error('Error removing bookmark:', error);
        alert('Error removing bookmark. Please try again later.');
    }
} 