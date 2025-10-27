(() => {
  const browserType = (() => {
    const userAgent = navigator.userAgent;
    if (userAgent.indexOf("Chrome") > -1 && userAgent.indexOf("Edge") === -1) {
      return "Chrome";
    } else if (userAgent.indexOf("Firefox") > -1) {
      return "Firefox";
    } else if (userAgent.indexOf("Safari") > -1 && userAgent.indexOf("Chrome") === -1) {
      return "Safari";
    } else if (userAgent.indexOf("CocCoc") > -1) {
      return "Cốc Cốc";
    } else if (userAgent.indexOf("Edge") > -1) {
      return "Edge";
    } else if (userAgent.indexOf("MSIE") > -1 || userAgent.indexOf("Trident/") > -1) {
      return "Internet Explorer";
    }
    return "Unknown";
  })();
  
  const supportedBrowsers = ["Chrome", "Safari", "Cốc Cốc", "Edge"];
  
  if (!supportedBrowsers.includes(browserType)) {
    document.body.innerHTML = `
      <div style="text-align: center; padding: 20px; font-family: Arial, sans-serif; background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; margin: 20px; border-radius: 8px;">
        <h1>Trình duyệt không được hỗ trợ</h1>
        <p>Rất tiếc, trình duyệt của bạn không được hỗ trợ.</p>
        <p>Nếu bạn đang truy cập qua Zalo, vui lòng thoát ứng dụng và mở lại bằng trình duyệt để tiếp tục.</p>
        <p>Vui lòng sử dụng một trong các trình duyệt sau:</p>
        <ul style="list-style: none; padding: 0;">
          <li>Chrome</li>
          <li>Safari</li>
          <li>Cốc Cốc</li>
          <li>Edge</li>
        </ul>
      </div>
    `;
  }
  
  if ("SharedWorker" in window) {
    let worker;
    try {
      worker = new SharedWorker("worker.js");
      worker.port.start();
      worker.port.postMessage("init");

      worker.port.onmessage = (e) => {
        if (e.data === "duplicate") {
          window.close();
        }
      };
    } catch (err) {
      enableLocalStorageLock();
    }
  } else {
    enableLocalStorageLock();
  }

  function enableLocalStorageLock() {
    window.addEventListener("storage", (e) => {
      if (e.key === "tool_opened" && e.newValue === "true") {
        window.close();
      }
    });
    localStorage.setItem("tool_opened", "true");
    window.addEventListener("beforeunload", () => {
      localStorage.removeItem("tool_opened");
    });
  }
  
  const inputManual = document.getElementById('inputManual');
  const inputFile = document.getElementById('inputFile');
  const manualInputArea = document.getElementById('accounts');
  const fileInput = document.getElementById('fileUpload');
  const fileInputDesc = document.getElementById('fileUploadDesc');
  const checkBtn = document.getElementById('checkButton');
  const stopBtn = document.getElementById('stopButton');
  const progressContainer = document.getElementById('progressContainer');
  const progressBar = document.getElementById('progressBar');
  const progressText = document.getElementById('progressText');
  const consoleLog = document.getElementById('consoleLog');
  const downloadSuccessTxt = document.getElementById('downloadSuccessTxt');
  const downloadErrorTxt = document.getElementById('downloadErrorTxt');
  const downloadWarningTxt = document.getElementById('downloadWarningTxt');
  const downloadSuccessExcel = document.getElementById('downloadSuccessExcel');
  const downloadErrorExcel = document.getElementById('downloadErrorExcel');
  const downloadWarningExcel = document.getElementById('downloadWarningExcel');
  const summaryText = document.getElementById('summaryText');
  const btnSpinner = document.getElementById('btnSpinner');
  const clearCacheBtn = document.getElementById('clearCacheBtn');
  const outputFormatRadios = document.querySelectorAll('input[name="outputFormat"]');

  const btnSuccessDropdown = document.getElementById('btnSuccessDropdown');
  const btnErrorDropdown = document.getElementById('btnErrorDropdown');
  const btnWarningDropdown = document.getElementById('btnWarningDropdown');
  const menuSuccess = document.getElementById('menuSuccess');
  const menuError = document.getElementById('menuError');
  const menuWarning = document.getElementById('menuWarning');

  let outputFormat = "pipe";
  outputFormatRadios.forEach(radio => {
    if (radio.checked) outputFormat = radio.value;
    radio.addEventListener('change', () => {
      outputFormat = radio.value;
      updateDownloadBtns();
    });
  });

  let allResults = [];
  let allErrors = [];
  let allWarnings = [];
  let isChecking = false;
  let totalAccounts = 0;
  let successCount = 0;
  let errorCount = 0;
  let warningCount = 0;
  let stopCheckingFlag = false;
  let stopCheckingController;
  let completedChecks = 0;
  let startTime;

  function createDataText(dataArr) {
    if (!dataArr || !dataArr.length) return '';
    if (outputFormat === "pipe") return dataArr.join('\n');
    return dataArr.map(line => {
      const idx = line.indexOf('|');
      if(idx === -1) return line.replace(/\|/g, ':');
      return line.slice(0, idx) + ':' + line.slice(idx + 1);
    }).join('\n');
  }

  function exportExcelByFormat(dataArr, fileName = "export.xlsx") {
    if (!dataArr || !dataArr.length) return;
    let rows;
    if (outputFormat === "pipe") {
      rows = dataArr.map(line => line.split('|').map(x => x.trim()));
    } else {
      rows = dataArr.map(line => {
        const idx = line.indexOf('|');
        if(idx === -1) return line.split(':').map(x => x.trim());
        const username = line.slice(0, idx);
        const rest = line.slice(idx + 1);
        return [username, ...rest.split('|').map(x => x.trim())];
      });
    }
    const ws = XLSX.utils.aoa_to_sheet(rows);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "Sheet1");
    const wbOut = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
    const blob = new Blob([wbOut], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  function createDownloadURL(dataArr) {
    const blob = new Blob([createDataText(dataArr)], { type: 'text/plain' });
    return URL.createObjectURL(blob);
  }

  function timestamp() {
    const d = new Date();
    return d.toISOString().slice(0,19).replace(/:/g,'_');
  }

  function toggleDropdownButtonState(btn, menu, hasData) {
    if (btn) {
      if (hasData) {
        btn.removeAttribute('disabled');
        btn.classList.remove('opacity-60', 'cursor-not-allowed');
        btn.onclick = e => {
          e.stopPropagation();
          menu.classList.toggle('hidden');
        };
      } else {
        btn.setAttribute('disabled', 'true');
        btn.classList.add('opacity-60', 'cursor-not-allowed');
        menu.classList.add('hidden');
        btn.onclick = null;
      }
    }
  }

  function updateDownloadBtns() {
    toggleDropdownButtonState(btnSuccessDropdown, menuSuccess, allResults.length > 0);
    toggleDropdownButtonState(btnErrorDropdown, menuError, allErrors.length > 0);
    toggleDropdownButtonState(btnWarningDropdown, menuWarning, allWarnings.length > 0);
    setupDownloadBtn(downloadSuccessTxt, allResults, 'thanh_cong');
    setupDownloadBtn(downloadErrorTxt, allErrors, 'that_bai');
    setupDownloadBtn(downloadWarningTxt, allWarnings, 'loi');
    setupExcelBtn(downloadSuccessExcel, allResults, 'thanh_cong');
    setupExcelBtn(downloadErrorExcel, allErrors, 'that_bai');
    setupExcelBtn(downloadWarningExcel, allWarnings, 'loi');
    updateSummary();
  }

  window.addEventListener("click", function(e){
    [menuSuccess, menuError, menuWarning].forEach(menu => {
      if (!menu.contains(e.target) && !menu.previousElementSibling.contains(e.target)) {
        menu.classList.add("hidden");
      }
    });
  });

  function setupDownloadBtn(btn, dataArray, prefix) {
    if (!btn) return;

    if (!dataArray.length) {
      btn.classList.add('opacity-50', 'cursor-not-allowed');
      btn.setAttribute('aria-disabled', 'true');
      btn.tabIndex = -1;
      btn.onclick = null;
      return;
    }

    btn.classList.remove('opacity-50', 'cursor-not-allowed');
    btn.removeAttribute('aria-disabled');
    btn.tabIndex = 0;

    btn.onclick = (e) => {
      e.preventDefault();
      const text = createDataText(dataArray);
      const blob = new Blob([text], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${prefix}_${timestamp()}.txt`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    };
  }

  function setupExcelBtn(btn, dataArray, prefix) {
    if (!btn) return;

    if (!dataArray.length) {
      btn.classList.add('opacity-50', 'cursor-not-allowed');
      btn.setAttribute('aria-disabled', 'true');
      btn.tabIndex = -1;
      btn.onclick = null;
      return;
    }

    btn.classList.remove('opacity-50', 'cursor-not-allowed');
    btn.removeAttribute('aria-disabled');
    btn.tabIndex = 0;

    btn.onclick = (e) => {
      e.preventDefault();

      let rows;
      if (outputFormat === "pipe") {
        rows = dataArray.map(line => line.split('|').map(x => x.trim()));
      } else {
        rows = dataArray.map(line => {
          const idx = line.indexOf('|');
          if(idx === -1) return line.split(':').map(x => x.trim());
          const username = line.slice(0, idx);
          const rest = line.slice(idx + 1);
          return [username, ...rest.split('|').map(x => x.trim())];
        });
      }

      const ws = XLSX.utils.aoa_to_sheet(rows);
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, "Sheet1");
      const wbOut = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });

      const blob = new Blob([wbOut], {
        type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${prefix}_${timestamp()}.xlsx`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    };
  }

  [[downloadSuccessTxt, () => allResults, 'thanh_cong', menuSuccess],
   [downloadErrorTxt,   () => allErrors,  'that_bai',  menuError],
   [downloadWarningTxt, () => allWarnings,'loi',       menuWarning]].forEach(([btn, getArr, prefix, menu]) => {
    btn.addEventListener('click', function(e) {
      if(btn.classList.contains('opacity-50') || btn.getAttribute('aria-disabled') === 'true') {
        e.preventDefault(); return;
      }
      if(!getArr().length) { e.preventDefault(); return; }
      btn.href = createDownloadURL(getArr());
      btn.download = `${prefix}_${timestamp()}.txt`;
      setTimeout(()=>URL.revokeObjectURL(btn.href), 5000);
      menu.classList.add('hidden');
    });
  });

  [[downloadSuccessExcel, () => allResults, 'thanh_cong', menuSuccess],
   [downloadErrorExcel,   () => allErrors,  'that_bai',  menuError],
   [downloadWarningExcel, () => allWarnings,'loi',       menuWarning]].forEach(([btn, getArr, prefix, menu]) => {
    btn.addEventListener('click', function(e) {
      if(btn.classList.contains('opacity-50') || btn.getAttribute('aria-disabled') === 'true') {
        e.preventDefault(); return;
      }
      if(!getArr().length) { e.preventDefault(); return; }
      exportExcelByFormat(getArr(), `${prefix}_${timestamp()}.xlsx`);
      menu.classList.add('hidden');
    });
  });

  function saveResultsToLocal() {
    const compressedResults = LZString.compressToUTF16(JSON.stringify(allResults));
    const compressedErrors = LZString.compressToUTF16(JSON.stringify(allErrors));
    const compressedWarnings = LZString.compressToUTF16(JSON.stringify(allWarnings));

    localStorage.setItem("acc_check_success", compressedResults);
    localStorage.setItem("acc_check_error", compressedErrors);
    localStorage.setItem("acc_check_warning", compressedWarnings);
    updateDownloadBtns();
  }

  function loadResultsFromLocal() {
    const compressedResults = localStorage.getItem("acc_check_success");
    const compressedErrors = localStorage.getItem("acc_check_error");
    const compressedWarnings = localStorage.getItem("acc_check_warning");

    if (compressedResults && compressedErrors && compressedWarnings) {
      allResults = JSON.parse(LZString.decompressFromUTF16(compressedResults) || "[]");
      allErrors = JSON.parse(LZString.decompressFromUTF16(compressedErrors) || "[]");
      allWarnings = JSON.parse(LZString.decompressFromUTF16(compressedWarnings) || "[]");
    
      successCount = allResults.length;
      errorCount = allErrors.length;
      warningCount = allWarnings.length;

      updateDownloadBtns();

      if (allResults.length + allErrors.length + allWarnings.length > 0) {
        log("🔥 Đã khôi phục kết quả trước đó từ cache. Có thể tải lại file nếu cần!", "info");
      }
    }
  }

  function clearResultsFromLocal() {
    localStorage.removeItem("acc_check_success");
    localStorage.removeItem("acc_check_error");
    localStorage.removeItem("acc_check_warning");
    allResults = [];
    allErrors = [];
    allWarnings = [];
    successCount = errorCount = warningCount = 0;
    updateDownloadBtns();
    log("🗑️ Đã xóa sạch dữ liệu cache.", "warning");
  }

  function log(msg, type='info') {
    if(!consoleLog) return;
    const time = new Date().toLocaleTimeString();
    const iconMap = {success:'✅', error:'❌', warning:'⚠️', info:'ℹ️'};
    const logLine = document.createElement('div');
    logLine.style.marginBottom = '3px';
    logLine.innerHTML = `<span>${iconMap[type]||''}</span> <span style="opacity:0.7;min-width:65px;display:inline-block;">[${time}]</span> <span>${msg}</span>`;
    consoleLog.appendChild(logLine);
    while (consoleLog.childNodes.length > 7) {
      consoleLog.removeChild(consoleLog.firstChild);
    }
    consoleLog.scrollTop = consoleLog.scrollHeight;
  }

  function clearConsole() {consoleLog.innerHTML = '';}

  function toggleInputMode() {
    if(inputManual.checked) {
      manualInputArea.disabled = false;
      manualInputArea.placeholder = "Mỗi tài khoản một dòng (username|password hoặc username:password).";
      fileInput.classList.add('hidden');
      fileInputDesc.classList.add('hidden');
      manualInputArea.classList.remove('hidden');
      manualInputArea.value = '';
    } else {
      manualInputArea.disabled = true;
      manualInputArea.value = '';
      manualInputArea.classList.add('hidden');
      fileInput.classList.remove('hidden');
      fileInputDesc.classList.remove('hidden');
    }
  }

  inputManual.addEventListener('change', toggleInputMode);
  inputFile.addEventListener('change', toggleInputMode);
  toggleInputMode();

  fileInput.addEventListener('change', e => {
    const file = e.target.files[0];
    if(!file) return;
    if(file.type !== "text/plain" && !file.name.endsWith(".txt")) {
      log('File không hợp lệ, chỉ nhận .txt!', 'error');
      fileInput.value = '';
      return;
    }
    const reader = new FileReader();
    reader.onload = (event) => {
      manualInputArea.value = event.target.result.trim();
      manualInputArea.classList.add('animate-pulse');
      setTimeout(() => manualInputArea.classList.remove('animate-pulse'), 500);
    };
    reader.readAsText(file);
  });

  function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  function removeCheckedAccount(acc) {
    let arr = manualInputArea.value.split('\n').map(l => l.trim()).filter(Boolean);
    arr = arr.filter(line => line !== acc);
    manualInputArea.value = arr.join('\n');
  }

  function updateProgress(completed) {
    const pct = (completed / totalAccounts) * 100;
    progressBar.style.width = pct + '%';
    progressBar.textContent = Math.floor(pct) + '%';
    const elapsed = (Date.now() - startTime) / 1000;
    const avg = completed > 0 ? elapsed / completed : 0;
    const remain = totalAccounts - completed;
    const est = Math.round(remain * avg);
    let estStr = '';
    if (est >= 3600) {
      const h = Math.floor(est / 3600);
      const m = Math.floor((est % 3600) / 60);
      estStr = `${h}h ${m}m`;
    } else if (est >= 60) {
      const m = Math.floor(est / 60);
      const s = est % 60;
      estStr = `${m}m ${s}s`;
    } else {
      estStr = `${est}s`;
    }
    progressText.textContent = `Đang kiểm tra ${completed} / ${totalAccounts} tài khoản | Ước tính còn: ${estStr}`;
  }

  function updateSummary() {
    summaryText.innerHTML = `
      <span class="text-green-400 font-semibold">Thành công: ${successCount}</span><br/>
      <span class="text-red-400 font-semibold">Thất bại: ${errorCount}</span><br/>
      <span class="text-yellow-400 font-semibold">Cần kiểm tra lại: ${warningCount}</span>
    `;
  }

  async function checkAccount(account, key, signal, retryCount = 0) {
    const mode = document.querySelector("input[name='dataMode']:checked").value;
    if (stopCheckingFlag) {
      log('Quá trình kiểm tra bị dừng.', 'info');
      return;
    }
    log(`Bắt đầu kiểm tra tài khoản: ${account}`, 'info');
    const parts = account.split(/[:|]/).map(p=>p.trim());
    if(parts.length < 2 || !parts[0] || !parts[1]) {
      log(`Định dạng tài khoản không hợp lệ, bỏ qua: ${account}`, 'error');
      completedChecks++; updateProgress(completedChecks); saveResultsToLocal(); return;
    }
    const [username, password, pass2] = parts;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000);
    if(username.includes('@') && !validateEmail(username)) {
      log(`Email không hợp lệ, bỏ qua: ${username}`, 'error');
      completedChecks++; updateProgress(completedChecks); saveResultsToLocal(); return;
    }
    let isReloadRetry = false;
    try {
      const resp = await fetch('https://toolacc.site/checkliquisun.php', {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-Requested-With': 'XMLHttpRequest'
        },
        body: new URLSearchParams({account: username, password, pass2, key}),
        signal
      });
      if (resp.status === 403) {
        stopCheckingFlag = true;
        const errorMsg = "❌ Bị nhảy IP máy hoặc TOOL hết hạn. Vui lòng xem hướng dẫn ở Tool1S.Vn";
        log(errorMsg, "error");
        return;
      }
      if (resp.status === 999) {
        stopCheckingFlag = true;
        const errorMsg = "❌ Key hết hạn";
        log(errorMsg, "error");
        return;
      }
      if (resp.status === 429) {
        stopCheckingFlag = true;
        const errorMsg = "❌ Quá nhiều yêu cầu! vui lòng thử lại sau.";
        log(errorMsg, "error");
        return;
      }
      if (resp.status === 524) {
        if (retryCount < 10) { 
          log(`🔁 Hệ thống đang kiểm tra lại tài khoản ${username}, đang thử lại... ${retryCount + 1}`, 'warning');
          isReloadRetry = true;
          return await checkAccount(account, key, signal, retryCount + 1); 
        } else {
          log(`❌ Hệ thống đang kiểm tra lại tài khoản ${username}. Đã thử lại tối đa, bỏ qua tài khoản này.`, 'error');
          if (mode === "newOnly") {
              allWarnings.push(`${username}|${password}`);
          }else{
              allWarnings.push(`${account}`);
          }
          warningCount++;
          removeCheckedAccount(account);
          saveResultsToLocal();
          return;
        }
      }
      if (!resp.ok) {
        if (retryCount < 10) { 
          log(`🔁 Hệ thống đang kiểm tra lại tài khoản ${username}, đang thử lại... ${retryCount + 1}`, 'warning');
          isReloadRetry = true;
          return await checkAccount(account, key, signal, retryCount + 1); 
        } else {
          log(`❌ Hệ thống đang kiểm tra lại tài khoản ${username}. Đã thử lại tối đa, bỏ qua tài khoản này.`, 'error');
          if (mode === "newOnly") {
              allWarnings.push(`${username}|${password}`);
          }else{
              allWarnings.push(`${account}`);
          }
          warningCount++;
          removeCheckedAccount(account);
          saveResultsToLocal();
          return;
        }
      } 
      const data = await resp.json();
      if (data.status === 'reload') {
        if(retryCount < 10) {
          log(`🔁 Hệ thống đang kiểm tra lại tài khoản ${username}, đang thử lại... ${retryCount + 1}`, 'warning');
          isReloadRetry = true;
          return await checkAccount(account, key, signal, retryCount + 1);
        } else {
          log(`❌ Hệ thống đang kiểm tra lại tài khoản ${username}. Đã thử lại tối đa, bỏ qua tài khoản này.`, 'error');
          if (mode === "newOnly") {
              allWarnings.push(`${username}|${password}`);
          }else{
              allWarnings.push(`${account}`);
          }
          warningCount++;
          saveResultsToLocal();
          removeCheckedAccount(account);
          return;
        }
      }
      if (data.status === "key_expired") {
        stopCheckingFlag = true;
        log(`❌ ${data.data}`, 'error');
        return;
      }
      if (data.status === 'success') {
          if (mode === "newOnly") {
            allResults.push(`${data.data.username}|${data.data.password}| TƯỚNG : ${data.data.tuong} | SKIN : ${data.data.skin} | SS : ${data.data.ss} [${data.data.listskinss}] | SSS : ${data.data.sss} [${data.data.listskinsss}] | ANIME : ${data.data.anime} [${data.data.listskinanime}] | AOV : ${data.data.aov} [${data.data.listskinaov}]`); 
          }else{
            allResults.push(`${account} | TƯỚNG : ${data.data.tuong} | SKIN : ${data.data.skin} | SS : ${data.data.ss} [${data.data.listskinss}] | SSS : ${data.data.sss} [${data.data.listskinsss}] | ANIME : ${data.data.anime} [${data.data.listskinanime}] | AOV : ${data.data.aov} [${data.data.listskinaov}]`); 
          }
        successCount++;
        log(`✔️ Thành công: ${username}`, 'success');
      } else if(data.status === 'error') {
        if (mode === "newOnly") {
            allErrors.push(`${username}|${password}| ${data.data}`);
        }else{
            allErrors.push(`${account}| ${data.data}`);
        }
        errorCount++;
        log(`❌ Thất bại: ${username} - ${data.data}`, 'error');
      }
      removeCheckedAccount(account);
      saveResultsToLocal();
    } catch (e) {
      clearTimeout(timeoutId);
      if (e.name === 'AbortError') {
        log(`Tài khoản ${username} chạy quá 30 giây, đang thử lại...`, 'warning');
        if (retryCount < 10) {
          return await checkAccount(account, key, signal, retryCount + 1);
        } else {
          log(`❌ Quá giới hạn retry, bỏ qua tài khoản ${username}.`, 'error');
          if (mode === "newOnly") allWarnings.push(`${username}|${password}`);
          else allWarnings.push(`${account}`);
          warningCount++;
          saveResultsToLocal();
          removeCheckedAccount(account);
        }
      } else {
        if (stopCheckingFlag) {
          log(`⏹️ Kiểm tra bị dừng: ${username}`, 'info');
        } else {
          if (mode === "newOnly") {
            allWarnings.push(`${username}|${password}`);
          } else {
            allWarnings.push(`${account}`);
          }
          warningCount++;
          log(`⚠️ Lỗi khi kiểm tra tài khoản: ${username} - ${e.message}`, 'warning');
        }
      }
    } finally {
      if (!isReloadRetry) {
        completedChecks++;
        updateProgress(completedChecks);
        updateSummary();
      }
    }
  }

  function processAccounts(accounts, key, signal) {
    return new Promise(resolve => {
      const concurrency = 10;
      let active = 0;
      let index = 0;
      const next = () => {
        if (stopCheckingFlag) {
          resolve();
          return;
        }
        if (index >= accounts.length && active === 0) {
          resolve();
          return;
        }
        while (active < concurrency && index < accounts.length) {
          const acc = accounts[index++];
          active++;
          checkAccount(acc, key, signal).finally(() => {
            active--;
            next();
          });
        }
      };
      next();
    });
  }
  
  async function startCheck() {
    if (isChecking) return;
    allResults = [];
    allErrors = [];
    allWarnings = [];
    totalAccounts = 0;
    successCount = 0;
    errorCount = 0;
    warningCount = 0;
    completedChecks = 0;
    stopCheckingFlag = false;
    stopCheckingController = new AbortController();
    const key = document.getElementById('key').value.trim();
    const rawInput = manualInputArea.value.trim();
    if (!key) {
      log('Thiếu key TOOL, vui lòng nhập key!', 'warning');
      return;
    }
    if (!rawInput) {
      log('Thiếu tài khoản, nhập vào để kiểm tra!', 'warning');
      return;
    }
    const accounts = rawInput.split('\n').map(l => l.trim()).filter(Boolean);
    if (accounts.length === 0) {
      log('Thiếu tài khoản hợp lệ để kiểm tra!', 'warning');
      return;
    }
    isChecking = true;
    totalAccounts = accounts.length;
    startTime = Date.now();
    clearConsole();
    progressContainer.classList.remove('hidden');
    updateProgress(0);
    checkBtn.disabled = true;
    stopBtn.disabled = false;
    btnSpinner.classList.remove('hidden');
    updateDownloadBtns();
    log('=== Bắt đầu kiểm tra danh sách tài khoản ===', 'info');
    await processAccounts(accounts, key, stopCheckingController.signal);
    progressContainer.classList.add('hidden');
    checkBtn.disabled = false;
    stopBtn.disabled = true;
    btnSpinner.classList.add('hidden');
    saveResultsToLocal();
    log(`Kết thúc! Tổng: ${totalAccounts}, Thành công: ${successCount}, Thất bại: ${errorCount}, Lỗi: ${warningCount}`, 'info');
    isChecking = false;
    updateDownloadBtns();
  }

  function stopCheck() {
    if (!isChecking) return;
    stopCheckingFlag = true;
    if (stopCheckingController) stopCheckingController.abort();
    checkBtn.disabled = false;
    stopBtn.disabled = true;
    btnSpinner.classList.add('hidden');
    progressContainer.classList.add('hidden');
    log('=== Đã dừng kiểm tra tài khoản ===', 'info');
    isChecking = false;
    updateDownloadBtns();
  }

  checkBtn.addEventListener('click', startCheck);
  stopBtn.addEventListener('click', stopCheck);
  clearCacheBtn.addEventListener('click', clearResultsFromLocal);

  document.addEventListener('DOMContentLoaded', function () {
    loadResultsFromLocal();
    updateDownloadBtns();
  });
})();
