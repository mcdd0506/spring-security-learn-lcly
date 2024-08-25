import {defineConfig} from 'vitepress'

// https://vitepress.dev/reference/site-config
export default defineConfig({
    base: '/spring-security-learn-lcly/',
    title: "Spring Security Study",
    description: "A Study Project For Spring Security",
    markdown: {
        math: true,
        lineNumbers: true
    },

    themeConfig: {
        head: [["link", {rel: "icon", href: "/spring-security-learn-lcly/icon.svg"}]],
        outline: [1, 4],
        lastUpdated: true,

        // https://vitepress.dev/reference/default-theme-config
        nav: [
            {text: 'Home', link: '/'},
            {
                text: '😶‍🌫️ 案例',
                items: [
                    {text: '🤣 第一个 SpringSecurity 程序', link: '/demo/demo01'},
                    {text: '😋 Spring Security 过滤器链', link: '/demo/demo02'},
                    {text: '🥶 Spring Security 的用户认证', link: '/demo/demo03'},
                    {text: '🫠 Spring Security 进阶功能', link: '/demo/demo04'},
                    {text: '🥸 Index ', link: '/demo/index.md'},
                ]
            },
            {
                text: "版本信息 😶‍🌫️",
                link: "/CHANGELOG",
            },
        ],

        sidebar: [
            {
                text: '😶‍🌫️ 案例',
                link: '/demo/index.md',
                collapsed: false,
                items: [
                    {text: '🤣 第一个 SpringSecurity 程序', link: '/demo/demo01'},
                    {text: '😋 Spring Security 过滤器链', link: '/demo/demo02'},
                    {text: '🥶 Spring Security 的用户认证', link: '/demo/demo03'},
                    {text: '🫠 Spring Security 进阶功能', link: '/demo/demo04'},
                ]
            },
            {
                text: "版本信息 😶‍🌫️",
                link: "/CHANGELOG",
            },
        ],
        footer: {
            copyright: "Copyright © 2024-present mcdd0506",
        },
        search: {
            provider: "local",
            options: {
                translations: {
                    button: {
                        buttonText: "搜索文档",
                        buttonAriaLabel: "搜索文档",
                    },
                    modal: {
                        noResultsText: "无法找到相关结果",
                        resetButtonTitle: "清除查询条件",
                        footer: {
                            selectText: "选择",
                            navigateText: "切换",
                        },
                    },
                },
            },
        },
        socialLinks: [
            {icon: "github", link: "https://github.com/mcdd0506"},
        ],
    }
})
