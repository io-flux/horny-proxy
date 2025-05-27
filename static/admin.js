document.addEventListener('DOMContentLoaded', () => {
    let backendApiBase = '';
    if (window.location.pathname.includes('/static/admin.html')) {
        backendApiBase = window.location.origin; 
    } else {
        backendApiBase = window.HORNY_PROXY_API_BASE || '';
    }

    const loginSection = document.getElementById('login-section');
    const adminContent = document.getElementById('admin-content');
    const loginForm = document.getElementById('login-form');
    const loginError = document.getElementById('login-error');
    const logoutButton = document.getElementById('logout-button');

    const shareForm = document.getElementById('share-form');
    const stashIdInput = document.getElementById('stash-id');
    const videoNameInput = document.getElementById('video-name');
    const daysValidInput = document.getElementById('days-valid');
    const resolutionInput = document.getElementById('resolution');
    const sharePasswordInput = document.getElementById('share-password');
    const showInGalleryInput = document.getElementById('show-in-gallery');
    const lookupTitleButton = document.getElementById('lookup-title-button');
    const shareMessage = document.getElementById('share-message');
    const shareError = document.getElementById('share-error');

    const shareTagForm = document.getElementById('share-tag-form');
    const tagNameInput = document.getElementById('tag-name');
    const tagIdInput = document.getElementById('tag-id');
    const shareIdTypeSelect = document.getElementById('share-id-type');
    const customShareIdInput = document.getElementById('custom-share-id');
    const tagDaysValidInput = document.getElementById('tag-days-valid');
    const tagResolutionInput = document.getElementById('tag-resolution');
    const tagSharePasswordInput = document.getElementById('tag-share-password');
    const tagShowInGalleryInput = document.getElementById('tag-show-in-gallery');
    const lookupTagButton = document.getElementById('lookup-tag-button');
    const tagShareMessage = document.getElementById('tag-share-message');
    const tagShareError = document.getElementById('tag-share-error');

    const sharedVideosTableBody = document.querySelector('#shared-videos-table tbody');
    const sharedTagsTableBody = document.querySelector('#shared-tags-table tbody');
    const refreshSharesButton = document.getElementById('refresh-shares');

    const editModal = document.getElementById('edit-modal');
    const editShareIdInput = document.getElementById('edit-share-id');
    const editVideoNameInput = document.getElementById('edit-video-name');
    const editDaysValidInput = document.getElementById('edit-days-valid');
    const editResolutionInput = document.getElementById('edit-resolution');
    const editSharePasswordInput = document.getElementById('edit-share-password');
    const editShowInGalleryInput = document.getElementById('edit-show-in-gallery');
    const saveEditButton = document.getElementById('save-edit-button');
    const cancelEditButton = document.getElementById('cancel-edit-button');
    const editError = document.getElementById('edit-error');

    let authToken = localStorage.getItem('horny_token');

    // Store passwords for shares created in this session
    const sharePasswords = {};

    function showLogin() {
        loginSection.style.display = 'flex'; 
        adminContent.style.display = 'none';
        localStorage.removeItem('horny_token');
        authToken = null;
    }

    function showAdmin() {
        loginSection.style.display = 'none';
        adminContent.style.display = 'flex'; 
        loginError.textContent = '';
        fetchSharedContent();
        setBaseDomain();
    }

    function clearMessages() {
        loginError.textContent = '';
        shareMessage.textContent = '';
        shareError.textContent = '';
        tagShareMessage.textContent = '';
        tagShareError.textContent = '';
        editError.textContent = '';
    }

    function logDebug(message, data = null) {
        console.log(`[DEBUG] ${new Date().toISOString()} ${message}`, data || '');
        if (data) {
            try {
                console.table(data);
            } catch (e) {
                // console.table might fail
            }
        }
    }

    async function apiRequest(url, method = 'GET', body = null, requiresAuth = true) {
        const fullUrl = backendApiBase + url;
        logDebug(`API Request: ${method} ${fullUrl}`, body);
        
        const headers = {};
        if (method !== 'POST' || url !== '/login') {
            headers['Content-Type'] = 'application/json';
        }

        if (requiresAuth) {
            if (!authToken) {
                showLogin();
                throw new Error('Not authenticated');
            }
            headers['Authorization'] = `Bearer ${authToken}`;
        }

        const options = {
            method,
            headers,
        };

        if (body) {
            if (method === 'POST' && url === '/login') {
                options.body = body; 
            } else {
                options.body = JSON.stringify(body);
            }
        }

        try {
            const response = await fetch(fullUrl, options);
            logDebug(`API Response: ${response.status} ${response.statusText} for ${method} ${fullUrl}`);
            
            if (response.status === 401 && requiresAuth) {
                showLogin();
                throw new Error('Authentication failed or token expired.');
            }
            if (!response.ok) {
                let errorData = { detail: `HTTP error! status: ${response.status}`};
                try {
                    errorData = await response.json();
                } catch (e) {
                    errorData.detail = response.statusText || errorData.detail;
                }
                logDebug('API Error Response:', errorData);
                throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
            }
            if (response.status === 204 || response.headers.get('content-length') === '0') {
                logDebug('API Success Response (No Content)');
                return null;
            }
            const responseData = await response.json();
            logDebug('API Success Response:', responseData);
            return responseData;
        } catch (error) {
            console.error(`API Request Error for ${method} ${fullUrl}:`, error.message);
            throw error; 
        }
    }

    function escapeHTML(str) {
        if (typeof str !== 'string') return '';
        const div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    function calculateDaysRemaining(expiresAt) {
        const now = new Date();
        const expiry = new Date(expiresAt);
        const diffTime = expiry - now;
        const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        return Math.max(0, diffDays);
    }

    function getRelativeTime(expiresAt) {
        const now = new Date();
        const expiry = new Date(expiresAt);
        const diffMs = expiry - now;
        
        if (diffMs < 0) return 'expired';
        
        const minutes = Math.floor(diffMs / 60000);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);
        const months = Math.floor(days / 30);
        const years = Math.floor(days / 365);
        
        if (minutes < 60) return `${minutes}m`;
        if (hours < 24) return `${hours}h`;
        if (days < 30) return `${days}d`;
        if (months < 12) return `${months}mo`;
        return `${years}y`;
    }
    
    function truncateText(text, maxLength) {
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }

    function copyToClipboard(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(() => {
                alert('Link copied to clipboard!');
            }).catch(err => {
                console.error('Failed to copy link:', err);
                fallbackCopy(text);
            });
        } else {
            fallbackCopy(text);
        }
    }

    function fallbackCopy(text) {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        try {
            document.execCommand('copy');
            alert('Link copied to clipboard!');
        } catch (err) {
            console.error('Fallback copy failed:', err);
            alert('Failed to copy link. Please copy manually: ' + text);
        }
        document.body.removeChild(textarea);
    }

    if (shareIdTypeSelect) {
        shareIdTypeSelect.addEventListener('change', () => {
            const customShareIdLabel = document.querySelector('label[for="custom-share-id"]');
            if (shareIdTypeSelect.value === 'custom') {
                customShareIdInput.style.display = 'block';
                customShareIdLabel.style.display = 'block';
                customShareIdInput.required = true;
            } else {
                customShareIdInput.style.display = 'none';
                customShareIdLabel.style.display = 'none';
                customShareIdInput.required = false;
                customShareIdInput.value = '';
            }
        });
    }

    if (authToken) {
        showAdmin();
    } else {
        showLogin();
    }

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            clearMessages();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            const formData = new URLSearchParams();
            formData.append('username', username);
            formData.append('password', password);

            try {
                const data = await apiRequest('/login', 'POST', formData, false);
                authToken = data.access_token;
                localStorage.setItem('horny_token', authToken);
                showAdmin();
            } catch (error) {
                console.error('Login failed:', error);
                loginError.textContent = error.message;
                showLogin();
            }
        });
    }
    
    if (logoutButton) {
        logoutButton.addEventListener('click', () => {
            showLogin();
        });
    }

    if (lookupTitleButton) {
        lookupTitleButton.addEventListener('click', async () => {
            clearMessages();
            const stashId = stashIdInput.value;
            if (!stashId) {
                shareError.textContent = 'Please enter a Stash Video ID.';
                return;
            }
            
            logDebug('Looking up video title for ID:', stashId);
            
            try {
                const data = await apiRequest(`/get_video_title/${stashId}`);
                if (data && data.title) {
                    videoNameInput.value = data.title;
                    logDebug('Video title found:', data.title);
                } else {
                    shareError.textContent = 'Could not find title for this ID.';
                    videoNameInput.value = '';
                    logDebug('No title found for video ID:', stashId);
                }
            } catch (error) {
                shareError.textContent = `Error looking up title: ${error.message}`;
                videoNameInput.value = '';
                logDebug('Error looking up video title:', error);
            }
        });
    }

    if (shareForm) {
        shareForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            clearMessages();

            const shareData = {
                video_name: videoNameInput.value,
                stash_video_id: parseInt(stashIdInput.value, 10),
                days_valid: parseInt(daysValidInput.value, 10),
                resolution: resolutionInput.value,
                password: sharePasswordInput.value || null,
                show_in_gallery: showInGalleryInput.checked
            };

            logDebug('Sharing video with data:', shareData);

            if (!shareData.video_name || isNaN(shareData.stash_video_id) || isNaN(shareData.days_valid) || !shareData.resolution) {
                shareError.textContent = 'Please fill in all required fields correctly.';
                return;
            }

            try {
                const result = await apiRequest('/share', 'POST', shareData);
                shareMessage.textContent = `Video shared successfully! URL: ${result.share_url}`;
                shareForm.reset();
                fetchSharedContent();
                logDebug('Video shared successfully:', result);
                // Store the password for this share
                if (shareData.password) {
                    const shareId = result.share_url.split('/').pop().split('?')[0];
                    sharePasswords[shareId] = shareData.password;
                }
            } catch (error) {
                shareError.textContent = `Failed to share video: ${error.message}`;
                logDebug('Failed to share video:', error);
            }
        });
    }
    
    if (lookupTagButton) {
        lookupTagButton.addEventListener('click', async () => {
            clearMessages();
            const tagName = tagNameInput.value.trim();
            if (!tagName) {
                tagShareError.textContent = 'Please enter a tag name.';
                return;
            }
            
            logDebug('Looking up tag:', tagName);
            
            try {
                const data = await apiRequest(`/lookup_tag/${encodeURIComponent(tagName)}`);
                logDebug('Tag lookup response:', data);
                
                if (data && data.tag_info) {
                    tagIdInput.value = data.tag_info.id;
                    tagIdInput.placeholder = `${data.tag_info.name} (${data.video_count} videos)`;
                    tagShareError.textContent = '';
                    logDebug('Tag found:', data.tag_info);
                } else {
                    tagShareError.textContent = 'Tag not found or has no videos.';
                    tagIdInput.value = '';
                    tagIdInput.placeholder = 'Auto-filled after lookup';
                    logDebug('Tag not found:', tagName);
                }
            } catch (error) {
                tagShareError.textContent = `Error looking up tag: ${error.message}`;
                tagIdInput.value = '';
                tagIdInput.placeholder = 'Auto-filled after lookup';
                logDebug('Error looking up tag:', error);
            }
        });
    }

    if (shareTagForm) {
        shareTagForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            clearMessages();

            let customShareId = null;
            if (shareIdTypeSelect.value === 'custom') {
                customShareId = customShareIdInput.value.trim();
                if (!customShareId) {
                    tagShareError.textContent = 'Please enter a custom share ID.';
                    return;
                }
            } else if (shareIdTypeSelect.value === 'tag-name') {
                customShareId = tagNameInput.value.trim().toLowerCase().replace(/[^a-z0-9-_]/g, '-').replace(/-+/g, '-');
                 if (!customShareId) {
                    tagShareError.textContent = 'Cannot derive share ID from empty tag name.';
                    return;
                }
            }

            const shareTagData = {
                tag_name: tagNameInput.value.trim(),
                tag_id: tagIdInput.value.trim(),
                days_valid: parseInt(tagDaysValidInput.value, 10),
                resolution: tagResolutionInput.value,
                password: tagSharePasswordInput.value || null,
                show_in_gallery: tagShowInGalleryInput.checked,
                custom_share_id: customShareId
            };

            logDebug('Sharing tag with data:', shareTagData);

            if (!shareTagData.tag_name || !shareTagData.tag_id || isNaN(shareTagData.days_valid) || !shareTagData.resolution) {
                tagShareError.textContent = 'Please fill in all required fields correctly.';
                return;
            }

            try {
                const result = await apiRequest('/share_tag', 'POST', shareTagData);
                tagShareMessage.textContent = `Tag shared successfully! URL: ${result.share_url} (${result.video_count} videos)`;
                shareTagForm.reset();
                tagIdInput.value = '';
                tagIdInput.placeholder = 'Auto-filled after lookup';
                if(shareIdTypeSelect) shareIdTypeSelect.value = 'random';
                if(customShareIdInput) customShareIdInput.style.display = 'none';
                const customShareIdLabel = document.querySelector('label[for="custom-share-id"]');
                if(customShareIdLabel) customShareIdLabel.style.display = 'none';
                fetchSharedContent();
                logDebug('Tag shared successfully:', result);
            } catch (error) {
                tagShareError.textContent = `Failed to share tag: ${error.message}`;
                logDebug('Failed to share tag:', error);
            }
        });
    }

    if (refreshSharesButton) {
        refreshSharesButton.addEventListener('click', fetchSharedContent);
    }

    async function fetchSharedContent() {
        logDebug('Fetching shared content...');
        try {
            const [videos, tags] = await Promise.all([
                apiRequest('/shared_videos'),
                apiRequest('/shared_tags')
            ]);
            logDebug('Fetched videos:', videos);
            logDebug('Fetched tags:', tags);
            renderSharedVideos(videos);
            renderSharedTags(tags);
        } catch (error) {
            console.error('Failed to fetch shared content:', error.message);
            if(sharedVideosTableBody) sharedVideosTableBody.innerHTML = '<tr><td colspan="4">Failed to load shared videos. Please try again.</td></tr>';
            if(sharedTagsTableBody) sharedTagsTableBody.innerHTML = '<tr><td colspan="4">Failed to load shared tags. Please try again.</td></tr>';
        }
    }

    function renderSharedVideos(videos) {
        if(!sharedVideosTableBody) return;
        sharedVideosTableBody.innerHTML = '';
        if (!videos || videos.length === 0) {
            sharedVideosTableBody.innerHTML = '<tr><td colspan="4">No videos shared yet.</td></tr>';
            return;
        }

        videos.forEach(video => {
            const row = document.createElement('tr');
            const relativeTime = getRelativeTime(video.expires_at);
            const shareUrl = video.share_url;
            const displayName = truncateText(video.video_name, 30);
            const fullName = video.video_name;

            // If the video has a password, append ?pwd=PASSWORD to the copy button's data-url
            let copyUrl = shareUrl;
            const shareId = video.share_id;
            if (video.has_password && sharePasswords[shareId]) {
                copyUrl += (shareUrl.includes('?') ? '&' : '?') + 'pwd=' + encodeURIComponent(sharePasswords[shareId]);
            }

            row.innerHTML = `
                <td title="${escapeHTML(fullName)}">${escapeHTML(displayName)}</td>
                <td>${video.hits}</td>
                <td>${relativeTime}</td>
                <td>
                    <button class="copy-button" data-url="${escapeHTML(copyUrl)}">Copy</button>
                    <button class="edit-button" 
                        data-share-id="${escapeHTML(video.share_id)}" 
                        data-video-name="${escapeHTML(video.video_name.split(' (')[0])}" 
                        data-days-valid="${calculateDaysRemaining(video.expires_at)}" 
                        data-resolution="${escapeHTML(video.resolution)}" 
                        data-has-password="${video.has_password}" 
                        data-show-in-gallery="${video.show_in_gallery}"
                        data-stash-video-id="${escapeHTML(video.stash_video_id.toString())}">Edit</button>
                    <button class="delete-button" data-share-id="${escapeHTML(video.share_id)}">Delete</button>
                </td>
            `;
            sharedVideosTableBody.appendChild(row);
        });

        addVideoTableButtonListeners();
    }

    function renderSharedTags(tags) {
        if(!sharedTagsTableBody) return;
        sharedTagsTableBody.innerHTML = '';
        if (!tags || tags.length === 0) {
            sharedTagsTableBody.innerHTML = '<tr><td colspan="4">No tags shared yet.</td></tr>';
            return;
        }

        tags.forEach(tag => {
            const row = document.createElement('tr');
            const relativeTime = getRelativeTime(tag.expires_at);
            const shareUrl = tag.share_url;
            const displayName = truncateText(`${tag.tag_name} (${tag.resolution})`, 30);
            const fullName = `${tag.tag_name} (${tag.resolution})`;

            row.innerHTML = `
                <td title="${escapeHTML(fullName)}">${escapeHTML(displayName)}</td>
                <td>${tag.hits}</td>
                <td>${relativeTime}</td>
                <td>
                    <button class="copy-button" data-url="${escapeHTML(shareUrl)}">Copy</button>
                    <button class="edit-tag-button" 
                        data-share-id="${escapeHTML(tag.share_id)}" 
                        data-tag-name="${escapeHTML(tag.tag_name)}" 
                        data-tag-id="${escapeHTML(tag.stash_tag_id)}"
                        data-days-valid="${calculateDaysRemaining(tag.expires_at)}" 
                        data-resolution="${escapeHTML(tag.resolution)}" 
                        data-has-password="${tag.has_password}" 
                        data-show-in-gallery="${tag.show_in_gallery}">Edit</button>
                    <button class="delete-tag-button" data-share-id="${escapeHTML(tag.share_id)}">Delete</button>
                </td>
            `;
            sharedTagsTableBody.appendChild(row);
        });

        addTagTableButtonListeners();
    }

    function addVideoTableButtonListeners() {
        document.querySelectorAll('#shared-videos-table .copy-button').forEach(button => {
            button.addEventListener('click', (e) => {
                const url = e.target.getAttribute('data-url');
                copyToClipboard(url);
            });
        });

        document.querySelectorAll('#shared-videos-table .edit-button').forEach(button => {
            button.addEventListener('click', (e) => {
                const shareId = e.target.getAttribute('data-share-id');
                const videoName = e.target.getAttribute('data-video-name');
                const daysValid = e.target.getAttribute('data-days-valid');
                const resolution = e.target.getAttribute('data-resolution');
                const showInGallery = e.target.getAttribute('data-show-in-gallery') === 'true';
                
                if(editShareIdInput) editShareIdInput.value = shareId;
                if(editVideoNameInput) editVideoNameInput.value = videoName;
                if(editDaysValidInput) editDaysValidInput.value = Math.max(1, parseInt(daysValid) || 7);
                if(editResolutionInput) editResolutionInput.value = resolution;
                if(editSharePasswordInput) editSharePasswordInput.value = '';
                if(editShowInGalleryInput) editShowInGalleryInput.checked = showInGallery;
                
                if(editModal) editModal.style.display = 'block';
                clearMessages();
            });
        });

        document.querySelectorAll('#shared-videos-table .delete-button').forEach(button => {
            button.addEventListener('click', async (e) => {
                const shareId = e.target.getAttribute('data-share-id');
                if (confirm(`Are you sure you want to delete share ${shareId}?`)) {
                    try {
                        await apiRequest(`/delete_share/${shareId}`, 'DELETE');
                        fetchSharedContent();
                    } catch (error) {
                        alert(`Failed to delete share: ${error.message}`);
                    }
                }
            });
        });
    }

    function addTagTableButtonListeners() {
        document.querySelectorAll('#shared-tags-table .copy-button').forEach(button => {
            button.addEventListener('click', (e) => {
                const url = e.target.getAttribute('data-url');
                copyToClipboard(url);
            });
        });

        document.querySelectorAll('#shared-tags-table .edit-tag-button').forEach(button => {
            button.addEventListener('click', (e) => {
                // For now, alert that tag editing is not yet implemented
                alert('Tag editing functionality coming soon!');
                // TODO: Implement tag editing modal similar to video editing
            });
        });

        document.querySelectorAll('#shared-tags-table .delete-tag-button').forEach(button => {
            button.addEventListener('click', async (e) => {
                const shareId = e.target.getAttribute('data-share-id');
                if (confirm(`Are you sure you want to delete tag share ${shareId}?`)) {
                    try {
                        await apiRequest(`/delete_tag_share/${shareId}`, 'DELETE');
                        fetchSharedContent();
                    } catch (error) {
                        alert(`Failed to delete tag share: ${error.message}`);
                    }
                }
            });
        });
    }
    
    if (cancelEditButton) {
        cancelEditButton.addEventListener('click', () => {
            if(editModal) editModal.style.display = 'none';
        });
    }

    if (saveEditButton) {
        saveEditButton.addEventListener('click', async () => {
            clearMessages();
            const shareId = editShareIdInput.value;
            
            const editButton = document.querySelector(`#shared-videos-table button.edit-button[data-share-id="${shareId}"]`);
            const stashVideoId = editButton ? parseInt(editButton.getAttribute('data-stash-video-id')) : 0;
            
            const updatedData = {
                video_name: editVideoNameInput.value,
                stash_video_id: stashVideoId, 
                days_valid: parseInt(editDaysValidInput.value, 10),
                resolution: editResolutionInput.value,
                password: editSharePasswordInput.value || null,
                show_in_gallery: editShowInGalleryInput.checked
            };

            if (!updatedData.video_name || isNaN(updatedData.days_valid) || !updatedData.resolution) {
                editError.textContent = 'Please fill in all required fields correctly.';
                return;
            }

            try {
                await apiRequest(`/edit_share/${shareId}`, 'PUT', updatedData);
                if(editModal) editModal.style.display = 'none';
                fetchSharedContent();
            } catch (error) {
                editError.textContent = `Failed to update share: ${error.message}`;
            }
        });
    }

    // Get base domain from shared videos response
    async function setBaseDomain() {
        try {
            const response = await fetch(backendApiBase + '/shared_videos', {
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('horny_token')}`
                }
            });
            if (response.ok) {
                const videos = await response.json();
                if (videos.length > 0 && videos[0].share_url) {
                    // Extract base domain from share URL
                    const shareUrl = new URL(videos[0].share_url);
                    const baseDomain = shareUrl.origin;
                    const logoLink = document.getElementById('logo-link');
                    if (logoLink) {
                        logoLink.href = baseDomain;
                    }
                }
            }
        } catch (error) {
            console.log('Could not determine base domain:', error);
        }
    }

    // Load site configuration
    async function loadSiteConfig() {
        try {
            const data = await apiRequest('/site_config', 'GET', null, false);
            if (data && data.site_name) {
                const siteNameElement = document.getElementById('site-name');
                if (siteNameElement) {
                    siteNameElement.textContent = data.site_name;
                }
                document.title = `Admin Panel - ${data.site_name}`;
            }
        } catch (error) {
            console.log('Could not load site config:', error);
        }
    }

    // Load site config on page load
    loadSiteConfig();
});
