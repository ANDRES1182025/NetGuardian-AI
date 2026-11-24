const API_URL = "https://netguardian-ai-qs24.onrender.com";

function getAuthHeaders() {
  const token = localStorage.getItem('token');
  const headers = { 'Content-Type': 'application/json' };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

// Obtener rol del usuario actual
function getUserRole() {
  return localStorage.getItem('user_role') || 'guest';
}

// Control de Navegación de Pestañas con Restricción de Roles
function switchTab(tabName, event) {
  const role = getUserRole();

  // Restricción: solo administradores pueden acceder a la pestaña de usuarios
  if (tabName === 'users' && role !== 'admin') {
    alert('Acceso restringido. Solo los administradores pueden acceder a la gestión de usuarios.');
    return;
  }

  document.querySelectorAll('.view-section').forEach(sec => sec.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));

  const activeSection = document.getElementById(`view-${tabName}`);
  if (activeSection) activeSection.classList.add('active');

  if (event) event.currentTarget.classList.add('active');
}

// Abrir / Cerrar Modal
function toggleModal(show) {
  const modal = document.getElementById('login-modal');
  if (show) modal.classList.remove('hidden');
  else modal.classList.add('hidden');
}

// Alternar entre Pestañas del Modal (Login / Registro)
function switchModalTab(type) {
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');
  const btnLogin = document.getElementById('btn-tab-login');
  const btnRegister = document.getElementById('btn-tab-register');
  const modalTitle = document.getElementById('modal-title');

  if (type === 'login') {
    loginForm.classList.remove('hidden');
    registerForm.classList.add('hidden');
    btnLogin.classList.add('active');
    btnRegister.classList.remove('active');
    modalTitle.innerHTML = `<i class="fa-solid fa-lock"></i> Acceso Analista SOC`;
  } else {
    loginForm.classList.add('hidden');
    registerForm.classList.remove('hidden');
    btnRegister.classList.add('active');
    btnLogin.classList.remove('active');
    modalTitle.innerHTML = `<i class="fa-solid fa-user-plus"></i> Registro de Analista`;
  }
}

function addLog(message, type = 'info') {
  const terminal = document.getElementById('terminal-logs');
  const line = document.createElement('div');
  line.className = 'log-line';
  const time = new Date().toLocaleTimeString();
  
  if (type === 'error') line.style.color = '#ef4444';
  if (type === 'warning') line.style.color = '#f59e0b';

  line.innerText = `[${time}] ${message}`;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

// Verificar conexión con Backend
async function checkBackendStatus() {
  try {
    const response = await fetch(`${API_URL}/`);
    const data = await response.json();
    
    if (data.status === "activo") {
      document.getElementById('api-status').innerText = "API & BD Conectadas";
      document.getElementById('api-status').style.color = "#10b981";
      document.getElementById('status-dot').className = "status-indicator active";
      addLog("[SYSTEM] Conexión establecida con el servidor FastAPI.");
    }
  } catch (error) {
    document.getElementById('api-status').innerText = "API Desconectada";
    document.getElementById('api-status').style.color = "#ef4444";
    document.getElementById('status-dot').className = "status-indicator";
    addLog(`[ERROR] No se pudo conectar con la API en ${API_URL}`, "error");
  }
}

function updateUIByRole() {
  const role = getUserRole();
  const optDeep = document.getElementById('opt-deep');
  const optSevAlto = document.getElementById('opt-sev-alto');
  const navUsers = document.getElementById('nav-users');
  const userDisplay = document.getElementById('user-display');
  const scannerSubtitle = document.getElementById('scanner-subtitle');
  const userDropdown = document.getElementById('user-dropdown');

  if (userDropdown) userDropdown.classList.add('hidden');

  if (role === 'guest') {
    optDeep.disabled = true;
    optDeep.innerText = "🔒 Inspección Profunda de Vulnerabilidades (IA)";
    optSevAlto.disabled = true;
    optSevAlto.innerText = "🔒 Alto (Requiere sesión)";

    if (document.getElementById('scan-type').value === 'deep') {
      document.getElementById('scan-type').value = 'quick';
    }
    if (document.getElementById('filter-severity').value === 'Alto') {
      document.getElementById('filter-severity').value = 'Medio';
    }

    navUsers.classList.add('hidden');
    userDisplay.innerText = "Acceso Analista";

    const count = parseInt(localStorage.getItem('guest_scan_count') || '0', 10);
    if (scannerSubtitle) {
      scannerSubtitle.innerText = `Modo Invitado: ${3 - count} escaneos gratuitos restantes de 3.`;
    }
  } else {
    optDeep.disabled = false;
    optDeep.innerText = "Inspección Profunda de Vulnerabilidades (IA)";
    optSevAlto.disabled = false;
    optSevAlto.innerText = "Alto";

    const savedUsername = localStorage.getItem('user_username');
    const email = localStorage.getItem('user_email') || 'Usuario';
    userDisplay.innerText = savedUsername || email.split('@')[0];

    if (role === 'admin') {
      navUsers.classList.remove('hidden');
    } else {
      navUsers.classList.add('hidden');
    }

    if (scannerSubtitle) {
      scannerSubtitle.innerText = `Sesión activa como ${userDisplay.innerText}. Todas las capacidades de análisis están disponibles.`;
    }
  }
}

// Cargar Métricas y Lista de Escaneos
async function loadDashboardStats() {
  try {
    const res = await fetch(`${API_URL}/scans/dashboard/stats`, {
      headers: getAuthHeaders()
    });
    if (res.ok) {
      const stats = await res.json();
      document.getElementById('stat-scans').innerText = stats.total_scans;
      
      const highThreats = stats.severity_distribution ? (stats.severity_distribution['Alto'] || 0) : 0;
      document.getElementById('stat-threats').innerText = highThreats;
    }

    const scansRes = await fetch(`${API_URL}/scans/`, {
      headers: getAuthHeaders()
    });
    if (scansRes.ok) {
      const scans = await scansRes.json();
      renderScansList(scans);
    }
  } catch (error) {
    console.error('Error al cargar datos:', error);
  }
}

// Renderizar Lista de Escaneos
function renderScansList(scans) {
  const container = document.getElementById('recent-scans-list');
  const role = getUserRole();

  if (!scans || scans.length === 0) {
    container.innerHTML = `<div class="empty-state" style="padding: 20px; text-align: center;"><p class="text-muted">No hay registros de escaneo activos.</p></div>`;
    return;
  }

  let htmlContent = '';

  if (role === 'admin') {
    htmlContent += `
      <div style="display: flex; justify-content: flex-end; margin-bottom: 12px;">
        <button onclick="clearAllScans()" style="background-color: #ef4444; color: white; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600;">
          <i class="fa-solid fa-trash-can"></i> Limpiar Todo el Historial (Admin)
        </button>
      </div>
    `;
  }

  htmlContent += scans.map(s => {
    const severityLower = (s.severity || 'bajo').toLowerCase();
    const canDelete = role === 'admin' || role === 'analyst';

    return `
      <div class="stat-card margin-top" style="justify-content: space-between; align-items: center; display: flex;">
        <div>
          <h4><i class="fa-solid fa-network-wired"></i> ${s.target}</h4>
          <p class="text-muted" style="font-size: 12px; margin-top: 4px;">${s.vulnerability_found}</p>
        </div>
        <div style="display: flex; align-items: center; gap: 10px;">
          <span class="badge badge-${severityLower}">${s.severity}</span>
          
          <button onclick="downloadPDF(${s.id})" title="Exportar Informe Ejecutivo PDF" style="background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.4); color: #3b82f6; border-radius: 6px; padding: 5px 10px; cursor: pointer; font-size: 12px; font-weight: 600; display: flex; align-items: center; gap: 6px; transition: all 0.2s;">
            <i class="fa-solid fa-file-pdf"></i> PDF
          </button>

          ${canDelete ? `
            <button onclick="deleteScan(${s.id})" title="Eliminar registro" style="background: transparent; border: none; color: #ef4444; cursor: pointer; font-size: 14px; padding: 4px 8px;">
              <i class="fa-solid fa-trash"></i>
            </button>
          ` : ''}
        </div>
      </div>
    `;
  }).join('');

  container.innerHTML = htmlContent;
}

// Renderizar la Telemetría de Reconocimiento Activo en la Vista del Escáner
function renderActiveTelemetryResults(telemetry) {
  const container = document.getElementById('active-telemetry-container');
  if (!container) return;

  if (!telemetry || (telemetry.total_open_ports === 0 && telemetry.total_paths_found === 0)) {
    container.innerHTML = `
      <div class="telemetry-empty">
        <i class="fa-solid fa-satellite-dish"></i>
        <p>No se detectaron puertos TCP abiertos ni rutas expuestas en el sondeo activo.</p>
      </div>
    `;
    container.classList.remove('hidden');
    return;
  }

  // Generación de lista de puertos
  let portsHtml = '';
  if (telemetry.open_ports && telemetry.open_ports.length > 0) {
    portsHtml = telemetry.open_ports.map(p => `
      <div class="port-badge">
        <span class="port-num"><i class="fa-solid fa-plug"></i> ${p.port}</span>
        <span class="port-service">${p.service}</span>
      </div>
    `).join('');
  } else {
    portsHtml = '<p class="text-muted" style="font-size:12px;">Sin puertos TCP estándar abiertos.</p>';
  }

  // Generación de lista de rutas descubiertas
  let pathsHtml = '';
  if (telemetry.discovered_paths && telemetry.discovered_paths.length > 0) {
    pathsHtml = telemetry.discovered_paths.map(path => {
      const isHighRisk = path.risk_level === 'Alto';
      const badgeClass = isHighRisk ? 'badge-alto' : 'badge-medio';
      return `
        <div class="path-row">
          <div class="path-info">
            <code>${path.path}</code>
            <span class="path-status">[HTTP ${path.status_code}]</span>
          </div>
          <span class="badge ${badgeClass}">${path.risk_level}</span>
        </div>
      `;
    }).join('');
  } else {
    pathsHtml = '<p class="text-muted" style="font-size:12px;">Sin directorios expuestos detectados.</p>';
  }

  container.innerHTML = `
    <div class="telemetry-card">
      <h3><i class="fa-solid fa-microchip"></i> Telemetría y Reconocimiento Activo de Red</h3>
      <div class="telemetry-grid">
        <div class="telemetry-box">
          <h4><i class="fa-solid fa-network-wired"></i> Puertos TCP Abiertos (${telemetry.total_open_ports})</h4>
          <div class="ports-flex">
            ${portsHtml}
          </div>
        </div>

        <div class="telemetry-box">
          <h4><i class="fa-solid fa-folder-tree"></i> Rutas y Endpoints Detectados (${telemetry.total_paths_found})</h4>
          <div class="paths-list">
            ${pathsHtml}
          </div>
        </div>
      </div>
    </div>
  `;
  container.classList.remove('hidden');
}

// Descargar informe PDF
async function downloadPDF(scanId) {
  try {
    addLog(`[REPORTS] Generando reporte ejecutivo PDF para el escaneo #${scanId}...`, "warning");
    
    const response = await fetch(`${API_URL}/scans/${scanId}/pdf`, {
      method: 'GET',
      headers: getAuthHeaders()
    });

    if (response.ok) {
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `NetGuardian_Report_Scan_${scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      
      addLog(`[SUCCESS] Reporte PDF #${scanId} descargado correctamente.`);
    } else {
      const err = await response.json();
      alert(err.detail || "No se pudo generar el PDF.");
      addLog(`[ERROR] Fallo al descargar PDF: ${err.detail || 'Error desconocido'}`, "error");
    }
  } catch (error) {
    addLog("[ERROR] Fallo de conexión al descargar el PDF.", "error");
  }
}

// Borrar un escaneo específico
async function deleteScan(scanId) {
  if (getUserRole() === 'guest') {
    alert('Debes iniciar sesión para eliminar registros de escaneo.');
    toggleModal(true);
    return;
  }

  if (!confirm(`¿Deseas eliminar el registro de análisis #${scanId}?`)) return;
  
  try {
    const response = await fetch(`${API_URL}/scans/${scanId}`, {
      method: 'DELETE',
      headers: getAuthHeaders()
    });
    if (response.ok) {
      addLog(`[SYSTEM] Escaneo #${scanId} eliminado correctamente.`);
      loadDashboardStats();
    } else {
      const err = await response.json();
      alert(err.detail || 'No se pudo eliminar el registro.');
    }
  } catch (error) {
    addLog("[ERROR] Fallo de conexión al intentar eliminar el escaneo.", "error");
  }
}

// Vaciar historial completo
async function clearAllScans() {
  if (getUserRole() !== 'admin') {
    alert('Acceso denegado. Solo el Administrador puede vaciar el historial.');
    return;
  }

  if (!confirm("¿Estás seguro de vaciar TODO el historial de escaneos guardados?")) return;

  try {
    const response = await fetch(`${API_URL}/scans/clear/all`, {
      method: 'DELETE',
      headers: getAuthHeaders()
    });
    if (response.ok) {
      addLog("[SYSTEM] Historial de escaneos vaciado por completo por el Administrador.");
      loadDashboardStats();
    } else {
      const err = await response.json();
      alert(err.detail || 'No se pudo vaciar el historial.');
    }
  } catch (error) {
    addLog("[ERROR] Fallo de conexión al intentar limpiar el historial.", "error");
  }
}

// Cargar Lista de Usuarios (Admin)
async function loadUsersList() {
  const role = getUserRole();
  const token = localStorage.getItem('token');

  if (role !== 'admin' || !token) return;

  const container = document.getElementById('users-table-container');
  try {
    const res = await fetch(`${API_URL}/users/`, {
      method: 'GET',
      headers: getAuthHeaders()
    });

    if (res.ok) {
      const users = await res.json();
      if (users.length === 0) {
        container.innerHTML = `<div class="empty-state"><p class="text-muted">No hay usuarios registrados.</p></div>`;
        return;
      }
      container.innerHTML = users.map(u => `
        <div class="user-row" style="display: flex; justify-content: space-between; align-items: center; padding: 12px; border-bottom: 1px solid rgba(255,255,255,0.1);">
          <div>
            <h4><i class="fa-solid fa-user-shield"></i> ${u.username}</h4>
            <p class="text-muted" style="font-size: 12px;">${u.email}</p>
          </div>
          <div style="display: flex; align-items: center; gap: 10px;">
            <select onchange="changeUserRole(${u.id}, this.value)" style="background: #1e293b; color: white; border: 1px solid #334155; padding: 4px 8px; border-radius: 4px; font-size: 12px;">
              <option value="analyst" ${u.role === 'analyst' ? 'selected' : ''}>Analista</option>
              <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Administrador</option>
              <option value="guest" ${u.role === 'guest' ? 'selected' : ''}>Invitado</option>
            </select>
            <span class="badge badge-bajo">ID: ${u.id}</span>
          </div>
        </div>
      `).join('');
    } else if (res.status === 401 || res.status === 403) {
      container.innerHTML = `<p class="text-muted" style="color: #ef4444;">No tienes autorización para consultar la lista de usuarios.</p>`;
      addLog("[AUTH] Intento no autorizado de consultar la lista de usuarios.", "error");
    } else {
      container.innerHTML = `<p class="text-muted">Error al obtener usuarios del sistema.</p>`;
    }
  } catch (err) {
    container.innerHTML = `<p class="text-muted">Fallo de conexión al cargar la lista de usuarios.</p>`;
  }
}

// Cambiar Rol de Usuario
async function changeUserRole(userId, newRole) {
  try {
    const res = await fetch(`${API_URL}/users/${userId}/role`, {
      method: 'PUT',
      headers: getAuthHeaders(),
      body: JSON.stringify({ role: newRole })
    });
    if (res.ok) {
      addLog(`[ADMIN] Rol del usuario ID ${userId} actualizado a: ${newRole}`);
      alert(`Rol actualizado a ${newRole} con éxito.`);
    } else {
      const err = await res.json();
      alert(err.detail || 'Error al actualizar el rol.');
    }
  } catch (err) {
    alert('Fallo de conexión al intentar cambiar el rol.');
  }
}

// Manejar perfil
function handleProfileClick() {
  const role = getUserRole();
  if (role === 'guest') {
    toggleModal(true);
  } else {
    const dropdown = document.getElementById('user-dropdown');
    if (dropdown) dropdown.classList.toggle('hidden');
  }
}

// Cerrar sesión
function logout() {
  localStorage.removeItem('token');
  localStorage.removeItem('user_email');
  localStorage.removeItem('user_username');
  localStorage.removeItem('user_role');
  addLog("[AUTH] Sesión cerrada.");
  updateUIByRole();
  loadDashboardStats();
  switchTab('dashboard');
}

// Listeners Principales
document.addEventListener("DOMContentLoaded", () => {
  checkBackendStatus();
  updateUIByRole();
  loadDashboardStats();

  const savedToken = localStorage.getItem('token');
  const savedEmail = localStorage.getItem('user_email');
  if (savedToken && savedEmail) {
    addLog(`[AUTH] Sesión activa restablecida para: ${savedEmail}`);
  }

  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;

    try {
      const response = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      if (response.ok) {
        const data = await response.json();
        localStorage.setItem('token', data.access_token);
        localStorage.setItem('user_email', email);
        localStorage.setItem('user_username', data.username || email.split('@')[0]);
        localStorage.setItem('user_role', data.role || 'analyst');
        
        toggleModal(false);
        addLog(`[AUTH] Sesión iniciada por: ${data.username || email}`);
        updateUIByRole();
        loadDashboardStats();
      } else {
        const err = await response.json();
        let errorDetail = err.detail || 'Credenciales inválidas o correo no registrado.';
        if (typeof errorDetail !== 'string') errorDetail = JSON.stringify(errorDetail);
        alert(errorDetail);
      }
    } catch (err) {
      addLog("[AUTH] Error intentando autenticar.", "error");
    }
  });

  document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('reg-username').value;
    const email = document.getElementById('reg-email').value;
    const password = document.getElementById('reg-password').value;

    try {
      const response = await fetch(`${API_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password, role: 'analyst' })
      });

      if (response.ok) {
        alert('¡Analista registrado con éxito! Ahora puedes iniciar sesión.');
        addLog(`[USER] Nuevo analista registrado: ${email}`);
        switchModalTab('login');
      } else {
        const errData = await response.json();
        let errorDetail = errData.detail || 'Verifique los datos';
        if (typeof errorDetail !== 'string') errorDetail = JSON.stringify(errorDetail);
        alert(`Error en registro: ${errorDetail}`);
      }
    } catch (err) {
      addLog("[USER] Error de conexión al registrar usuario.", "error");
    }
  });

  // Manejador del Escáner IA con captura de Telemetría Activa
  document.getElementById('scan-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const role = getUserRole();
    const target = document.getElementById('scan-target').value;
    const inspectionType = document.getElementById('scan-type').value;
    const severity = document.getElementById('filter-severity').value;
    const btn = document.getElementById('btn-scan');

    if (role === 'guest') {
      let count = parseInt(localStorage.getItem('guest_scan_count') || '0', 10);
      if (count >= 3) {
        alert("Has alcanzado el límite máximo de 3 escaneos de prueba como invitado. Por favor, inicia sesión o regístrate para continuar.");
        toggleModal(true);
        return;
      }
    }

    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Ejecutando Reconocimiento y Motor IA...`;
    
    addLog(`[SCAN] Iniciando análisis táctico sobre: ${target} (Tipo: ${inspectionType})...`, "warning");

    try {
      const res = await fetch(`${API_URL}/scans/run`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          target: target,
          inspection_type: inspectionType,
          severity: severity,
          user_id: 1
        })
      });

      if (res.ok) {
        const responseData = await res.json();
        const ai = responseData.ai_details;

        if (role === 'guest') {
          let count = parseInt(localStorage.getItem('guest_scan_count') || '0', 10) + 1;
          localStorage.setItem('guest_scan_count', count.toString());
          updateUIByRole();
        }

        addLog(`[SUCCESS] Análisis finalizado con severidad: ${ai.depth_level || ai.severity}`);
        addLog(`[SUMMARY] ${ai.summary}`);

        if (ai.detected_entities && ai.detected_entities.length > 0) {
          ai.detected_entities.forEach(entity => {
            addLog(`[FINDING] ${entity}`);
          });
        }

        // Renderizar el contenedor de Telemetría Activa
        if (ai.active_telemetry) {
          renderActiveTelemetryResults(ai.active_telemetry);
          addLog(`[RECON] Puertos abiertos: ${ai.active_telemetry.total_open_ports} | Rutas halladas: ${ai.active_telemetry.total_paths_found}`);
        }

        loadDashboardStats();
      } else {
        const err = await res.json();
        let formattedError = "Error en el servidor";

        if (typeof err.detail === 'string') {
          formattedError = err.detail;
        } else if (Array.isArray(err.detail)) {
          formattedError = err.detail.map(d => (d.msg ? d.msg.replace(/^Value error,\s*/i, '') : JSON.stringify(d))).join(' | ');
        } else if (typeof err.detail === 'object' && err.detail !== null) {
          formattedError = err.detail.msg || JSON.stringify(err.detail);
        }

        addLog(`[ERROR] No se pudo completar el análisis: ${formattedError}`, "error");

        if (res.status === 403 && role === 'guest') {
          alert(formattedError);
          toggleModal(true);
        }
      }
    } catch (err) {
      addLog("[ERROR] Fallo de conexión con la API en FastAPI.", "error");
    } finally {
      btn.disabled = false;
      btn.innerHTML = `<i class="fa-solid fa-radar"></i> Iniciar Escaneo`;
    }
  });

  window.addEventListener('click', (e) => {
    const profileBtn = document.getElementById('user-profile-btn');
    const dropdown = document.getElementById('user-dropdown');
    
    if (profileBtn && dropdown && !profileBtn.contains(e.target) && !dropdown.contains(e.target)) {
      dropdown.classList.add('hidden');
    }
  });
});
