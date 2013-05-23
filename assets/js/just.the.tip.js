(function ($) {
  /**
   * Just The Tip
   *
   * Tooltips for those who just want the tip.
   *
   * @copyright 2013 Mashape
   * @author Nijiko Yonskai
   *
   * @param  {String} className Tooltip Classname, created if it doesn't exist.
   * @param  {Number} arrow     Arrow size, in pixels.
   * @param  {Number} x         Tooltip x coordinate offset
   * @param  {Number} y         Tooltip y coordinate offset
   * @return {Object}           Self Reference, Jquery Plugin
   */
  $.fn.justTheTip = function (className, arrow, x, y) {
    var tip = {
      opts: {
        target: $(this),
        self: className || '.just-the-tip',
        position: 'top',
        hideOnSelf: false,
        style: false,
        speed: void 0,
        delay: 100,
        timeout: 0,
        attr: [
          'data-title'
        ],
        _i: 0,
        _magic: [
          'fade', 'slide'
        ],
        _supported: [
          'top', 'top-left', 'top-right',
          'bottom', 'bottom-left', 'bottom-right'
        ],
        _size: {
          arrow: typeof arrow === 'number' ? arrow : 0,
          height: 0,
          width: 0,
          window: {
            width: 0,
            height: 0,
            left: 0
          },
          container: {
            width: 0,
            height: 0
          },
          offset: {
            x: typeof x === 'number' ? x : 0,
            y: typeof y === 'number' ? y : 0,
            top: 0,
            left: 0,
            bottom: 0,
            right: 0
          }
        }
      }
    };

    tip.hideOnSelf = function () {
      this.opts.hideOnSelf = true;
      return this;
    };

    tip.timeout = function (ms) {
      this.opts.timeout = typeof ms === 'number' ? ms : 0;
      return this;
    };

    tip.delay = function (ms) {
      this.opts.delay = typeof ms === 'number' ? ms : 0;
      return this;
    };

    tip.attr = function (attr) {
      if (Object.prototype.toString.call(attr) === '[object Array]') this.opts.attr = attr;
      return this;
    };

    tip.animate = function (style, ms) {
      this.opts.style = (!$.inArray(style.toLowerCase(), this.opts._magic)) ? this.opts._supported[0] : style.toLowerCase();
      this.opts.speed = typeof ms === 'number' ? ms : this.opts.speed;
      return this;
    };

    tip.pos = function (type) {
      this.opts.position = (!$.inArray(type.toLowerCase(), this.opts._supported)) ? this.opts._supported[0] : type.toLowerCase();
      return this;
    };

    tip.arrow = function (size) {
      this.opts._size.arrow = typeof size === 'number' ? size : 0;
      return this;
    };

    tip._build = function (attr) {
      var cattr, html = '', $opts = this.opts; attr = attr || $opts.attr;
      for($opts._i = 0; $opts._i < attr.length; $opts._i++) {
        if (!(cattr = $opts.target.attr(attr[$opts._i]))) continue;
        if ((cattr[0] === '#' || cattr[0] === '.') && ($(cattr).length)) cattr = $(cattr).html();
        html += '<div class="' + attr[$opts._i].replace(/data\-/, '') + '">' + cattr + '</div>';
      }

      if (html !== '') {
        this.opts.self.html('<div class="jtt-inner">' + html + '</div>');
        return this._calculate();
      }
    };

    tip._calculateScreen = function () {
      var $size = this.opts._size;

      if (($size.offset.left - $size.window.left) < 0) {
        $size.offset.left = $size.window.left + 10;
      }

      if ((($size.offset.left + $size.width) - $size.window.left) > $size.window.width) {
        $size.offset.left = ($size.window.width + $size.window.left / 4) - $size.width;
      }
    };

    tip._calculate = function () {
      var $opts = this.opts, $size = $opts._size;
      var offset = $opts.target.offset(), difference;
      $size.width = $opts.self.outerWidth(false);
      $size.height = $opts.self.outerHeight(false);
      $size.container.width = $opts.target.outerWidth(false);
      $size.container.height = $opts.target.outerHeight(false);
      $size.window.width = $(window).width();
      $size.window.height = $(window).height();
      $size.window.left = $(window).scrollLeft();

      if (this.opts.position === 'top') {
        difference = (offset.left + $size.width) - (offset.left + $size.container.width);
        $size.offset.left = (offset.left + $size.offset.x) - (difference / 2);
        $size.offset.top = (offset.top - $size.height) - $size.offset.y - $size.arrow;
        this._calculateScreen();

        if ((offset.top - $size.height - 11) < 0)
          $size.offset.top = 0;
      }

      if (this.opts.position === 'top-left') {
        $size.offset.left = (offset.left - ($size.container.width / 3.3)) + $size.offset.x;
        $size.offset.top = (offset.top - ($size.height / 2)) - $size.offset.y - $size.arrow;
        this._calculateScreen();
      }

      if (this.opts.position === 'top-right') {
        $size.offset.left = (offset.left + ($size.container.width * 1.5) + $size.offset.x) - $size.width;
        $size.offset.top = (offset.top - $size.height) - $size.offset.y - $size.arrow;
        this._calculateScreen();
      }

      if (this.opts.position === 'bottom') {
        difference = (offset.left + $size.width + $size.offset.x) - (offset.left + $size.container.width);
        $size.offset.left = offset.left - (difference / 2);
        $size.offset.top = (offset.top + ($size.container.height / 1.5)) + $size.offset.y + (10 + $size.arrow);
        this._calculateScreen();
      }

      if (this.opts.position === 'bottom-left') {
        $size.offset.left = (offset.left - ($size.container.width / 1.5)) + $size.offset.x;
        $size.offset.top = (offset.top + ($size.container.height / 1.5)) + $size.offset.y + (10 + $size.arrow);
        this._calculateScreen();
      }

      if (this.opts.position === 'bottom-right') {
        $size.offset.left = (offset.left + ($size.container.width * 1.5) + $size.offset.x) - $size.width;
        $size.offset.top = (offset.top + ($size.container.height / 1.5)) + $size.offset.y + (10 + $size.arrow);
        this._calculateScreen();
      }

      $opts.self.css({
        'top': Math.ceil($size.offset.top),
        'left': Math.ceil($size.offset.left)
      });

      return this;
    };

    tip._magic = function (state, e) {
      state = state.toLowerCase();
      var $target = $(e.target),
          $opts = this.opts,
          $self = $opts.self,
          $size = $opts._size,
          $style = state;

      if ($opts.style)
        if ($opts.style === 'fade')
          $style = state === 'show' ? 'fadeIn' : 'fadeOut';
        else if ($opts.style === 'slide')
          $style = state === 'show' ? (
            $opts.position === 'top' ? 'slideDown' : 'slideUp'
          ) : (
            $opts.position === 'top' ? 'slideUp' : 'slideDown'
          );

      $self[$style]($opts.speed);
    };

    tip._mouseenter = function (e) {
      var $this = this,
          $opts = $this.opts,
          $target = $(e.relatedTarget || e.target),
          $ontoTip = ($target.closest($opts.self.selector)[0] === $opts.self[0]),
          $ontoTarget = ($target === $opts.target);

      setTimeout(function () {
        if ($opts.self.css('display') === 'block' && ($ontoTip || $ontoTarget)) {
          try {
            e.preventDefault();
            e.stopImmidiatePropagation();
          } catch (err) {} return;
        }

        $opts.self.bind('mouseleave', $.proxy(tip._mouseleave, $this));
        return $this._build()._magic('show', e);
      }, $opts.delay);
    };

    tip._mouseleave = function (e) {
      var $this = this,
          $opts = $this.opts,
          $target = $(e.relatedTarget || e.target),
          $ontoTip = ($target.closest($opts.self.selector)[0] === $opts.self[0]),
          $ontoTarget = ($target === $opts.target);

      setTimeout(function () {
        if ($opts.self.css('display') === 'block' && ($ontoTip || $ontoTarget)) {
          try {
            e.preventDefault();
            e.stopImmidiatePropagation();
          } catch (err) {} return;
        }

        $opts.self.unbind('mouseleave', tip._mouseleave);
        return $this._magic('hide', e);
      }, $opts.delay);
    };

    tip._init = function () {
      var $this = this;

      // Check and create tooltip if needed.
      if ($($this.opts.self).length < 1) {
        $('body').append('<div class="' + (className || 'just-the-tip') + '"></div>');
      }

      $this.opts.self = $($this.opts.self);
      $(this).bind('mouseenter', $.proxy(tip._mouseenter, $this));
      $(this).bind('mouseleave', $.proxy(tip._mouseleave, $this));

      return this;
    };

    for (var i in tip)
      if (tip.hasOwnProperty(i) || i !== 'opts')
        this[i] = tip[i];

    return this._init();
  };
})(jQuery);