// GuardianWAF Biometric Data Collector
// Collects mouse, keyboard, and scroll events for bot detection
// Minified version for production use

(function() {
  'use strict';

  // Configuration
  var CONFIG = {
    endpoint: '/gwaf/biometric/collect',
    sessionHeader: 'X-Session-ID',
    batchSize: 10,
    flushInterval: 5000,
    maxEvents: 1000
  };

  // Session ID management
  function getSessionId() {
    var sessionId = sessionStorage.getItem('gwaf_session_id');
    if (!sessionId) {
      sessionId = 'sess_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
      sessionStorage.setItem('gwaf_session_id', sessionId);
    }
    return sessionId;
  }

  // Event buffer
  var eventBuffer = [];
  var eventCount = 0;

  // Utility functions
  function throttle(func, limit) {
    var inThrottle;
    return function() {
      var args = arguments;
      var context = this;
      if (!inThrottle) {
        func.apply(context, args);
        inThrottle = true;
        setTimeout(function() { inThrottle = false; }, limit);
      }
    };
  }

  function sendEvents() {
    if (eventBuffer.length === 0) return;

    var events = eventBuffer.splice(0, eventBuffer.length);

    var xhr = new XMLHttpRequest();
    xhr.open('POST', CONFIG.endpoint, true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.setRequestHeader(CONFIG.sessionHeader, getSessionId());
    xhr.send(JSON.stringify({ events: events }));
  }

  function queueEvent(event) {
    if (eventCount >= CONFIG.maxEvents) return;
    eventBuffer.push(event);
    eventCount++;

    if (eventBuffer.length >= CONFIG.batchSize) {
      sendEvents();
    }
  }

  // Mouse event handlers
  var lastMousePos = { x: 0, y: 0 };
  var lastMouseTime = 0;

  function handleMouseMove(e) {
    var now = Date.now();
    // Throttle to max 20 events per second
    if (now - lastMouseTime < 50) return;
    lastMouseTime = now;

    queueEvent({
      type: 'mouse',
      subtype: 'move',
      x: e.clientX,
      y: e.clientY,
      ts: now
    });

    lastMousePos = { x: e.clientX, y: e.clientY };
  }

  function handleMouseClick(e) {
    queueEvent({
      type: 'mouse',
      subtype: 'click',
      x: e.clientX,
      y: e.clientY,
      button: e.button,
      ts: Date.now()
    });
  }

  function handleMouseDown(e) {
    queueEvent({
      type: 'mouse',
      subtype: 'down',
      x: e.clientX,
      y: e.clientY,
      button: e.button,
      ts: Date.now()
    });
  }

  function handleMouseUp(e) {
    queueEvent({
      type: 'mouse',
      subtype: 'up',
      x: e.clientX,
      y: e.clientY,
      button: e.button,
      ts: Date.now()
    });
  }

  // Keyboard event handlers
  function handleKeyDown(e) {
    queueEvent({
      type: 'keyboard',
      subtype: 'down',
      key: e.key,
      code: e.code,
      ts: Date.now()
    });
  }

  function handleKeyUp(e) {
    queueEvent({
      type: 'keyboard',
      subtype: 'up',
      key: e.key,
      code: e.code,
      ts: Date.now()
    });
  }

  function handleKeyPress(e) {
    queueEvent({
      type: 'keyboard',
      subtype: 'press',
      key: e.key,
      code: e.code,
      ts: Date.now()
    });
  }

  // Scroll event handler
  var scrollTimeout;
  function handleScroll(e) {
    clearTimeout(scrollTimeout);
    scrollTimeout = setTimeout(function() {
      queueEvent({
        type: 'scroll',
        x: window.scrollX,
        y: window.scrollY,
        dx: e.deltaX || 0,
        dy: e.deltaY || 0,
        ts: Date.now()
      });
    }, 50);
  }

  // Fingerprinting data collection
  function collectFingerprint() {
    var fp = {
      type: 'fingerprint',
      ts: Date.now()
    };

    // Screen info
    fp.screen = {
      width: screen.width,
      height: screen.height,
      colorDepth: screen.colorDepth,
      pixelRatio: window.devicePixelRatio || 1
    };

    // Browser info
    fp.language = navigator.language || navigator.userLanguage;
    fp.platform = navigator.platform;
    fp.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;

    // Canvas fingerprint
    try {
      var canvas = document.createElement('canvas');
      var ctx = canvas.getContext('2d');
      canvas.width = 200;
      canvas.height = 50;

      // Draw text
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(0, 0, 200, 50);
      ctx.fillStyle = '#069';
      ctx.fillText('GuardianWAF FP v1.0', 2, 15);

      fp.canvas = canvas.toDataURL();
    } catch (e) {
      fp.canvas = 'undefined';
    }

    // WebGL fingerprint
    try {
      var canvas2 = document.createElement('canvas');
      var gl = canvas2.getContext('webgl') || canvas2.getContext('experimental-webgl');
      if (gl) {
        var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
          fp.webgl = {
            vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
            renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
          };
        }
      }
    } catch (e) {
      fp.webgl = 'undefined';
    }

    // Plugins
    fp.plugins = [];
    if (navigator.plugins) {
      for (var i = 0; i < navigator.plugins.length; i++) {
        fp.plugins.push(navigator.plugins[i].name);
      }
    }

    queueEvent(fp);
  }

  // Touch event handlers (mobile)
  function handleTouchStart(e) {
    var touch = e.touches[0];
    queueEvent({
      type: 'touch',
      subtype: 'start',
      x: touch.clientX,
      y: touch.clientY,
      ts: Date.now()
    });
  }

  function handleTouchMove(e) {
    var touch = e.touches[0];
    queueEvent({
      type: 'touch',
      subtype: 'move',
      x: touch.clientX,
      y: touch.clientY,
      ts: Date.now()
    });
  }

  function handleTouchEnd(e) {
    queueEvent({
      type: 'touch',
      subtype: 'end',
      ts: Date.now()
    });
  }

  // Initialize
  function init() {
    // Don't run in iframes unless explicitly allowed
    if (window.self !== window.top && !window.GWAF_ALLOW_IFRAME) {
      return;
    }

    // Mouse events
    document.addEventListener('mousemove', throttle(handleMouseMove, 50), { passive: true });
    document.addEventListener('click', handleMouseClick, true);
    document.addEventListener('mousedown', handleMouseDown, true);
    document.addEventListener('mouseup', handleMouseUp, true);

    // Keyboard events
    document.addEventListener('keydown', handleKeyDown, true);
    document.addEventListener('keyup', handleKeyUp, true);
    document.addEventListener('keypress', handleKeyPress, true);

    // Scroll events
    window.addEventListener('scroll', throttle(handleScroll, 100), { passive: true });
    window.addEventListener('wheel', throttle(handleScroll, 100), { passive: true });

    // Touch events (mobile)
    document.addEventListener('touchstart', handleTouchStart, { passive: true });
    document.addEventListener('touchmove', throttle(handleTouchMove, 50), { passive: true });
    document.addEventListener('touchend', handleTouchEnd, { passive: true });

    // Collect fingerprint on load
    if (document.readyState === 'complete') {
      collectFingerprint();
    } else {
      window.addEventListener('load', collectFingerprint);
    }

    // Periodic flush
    setInterval(sendEvents, CONFIG.flushInterval);

    // Flush on page unload
    window.addEventListener('beforeunload', sendEvents);
    window.addEventListener('pagehide', sendEvents);
  }

  // Expose API
  window.GuardianWAF = {
    getSessionId: getSessionId,
    flush: sendEvents,
    version: '1.0.0'
  };

  // Start
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
